package mitm

// Delivery layer Этапа 2 (ветка content-filter-engine): ТОЧЕЧНАЯ
// доставка cosmetic CSS на dzen.ru. Никакого глобального MITM.
//
// Схема: DNS отдаёт для dzen.ru виртуальный адрес 10.0.0.3 -> маршрут
// 10.0.0.3/32 заворачивает TCP в движок -> здесь mini-MITM С ТЕМ ЖЕ
// пользовательским CA приложения: TLS с certForName(sni), HTTP/1.1,
// запрос к РЕАЛЬНОМУ dzen (IP резолвится ВНЕШНЕЙ цепочкой, не нашим
// DNS — иначе петля), в text/html инжектится CSS из правил косметики.
// Любая ошибка -> соединение просто закрывается (лог DZEN_*).

import (
	"bufio"
	"errors"
	"compress/gzip"
	"encoding/json"
	"crypto/sha256"
	"crypto/x509"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const dzenFakeIP = "10.0.0.3"

// CSS из cosmetic_rules.txt (слой Kotlin держит полный парсер; для
// delivery-слоя достаточно зафиксированных селекторов первого кейса).
const dzenCSS = `[data-ad-type="direct"],
[data-ad-type="banner"],
div[aria-label="Лента Дзена"] article:has(> div[data-ad-type="direct"]),
div[id^="ad-"][class*="__isStretched"],
div[class*="MyTargetAdvert"],
.card-rtb,
[class*="adBox"],
div[data-testid="bottom-ad"],
div[class*="__advertItem "],
div[class^="desktop2--redesign-feed__"] div:has(> article[class*="--card-rtb__"]),
div[aria-label="Лента Дзена"] div + article[class*="--card-rtb__"],
div[class^="dzen-desktop--feed__itemWrap-"],
div[class^="dzen-desktop--"][class*="__cardWrapper-"] ~ article:has([class*="__adBox-"]),
div[class*="topContent"][class*="mobile__hasBanner"],
div[class*="news"] > div[class*="_banner_"],
.zenad-card-rtb,
.news-mt-advert,
.mg-advert > div[class*="loader"],
div[class*="Advert_"],
div[class^="BrandingAdvert"],
.news-advert-column,
.article-render-mobile__embed_embed-type_yandex-direct,
div[class^="dzen-desktop--banner-"],
div[class*="-corner-banner__"],
div[class^="content--dzen-pro-"],
div[class^="dzen-mobile__bannerMain-"],
.feed__item article[class*="_is"]:not([class*="__card"]):not(:has(> div.short-video-carousel-view)) { display: none !important; }
`

func isDzenHost(h string) bool {
	h = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
	return h == "dzen.ru" || h == "www.dzen.ru" || h == "m.dzen.ru"
}

// dzenFakeDNSAnswer: A-запись -> 10.0.0.3; AAAA -> NOERROR пустой
// (клиент возьмёт наш A и пойдёт через фильтр).
func dzenFakeDNSAnswer(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	i := 12
	for i < len(query) {
		l := int(query[i])
		i++
		if l == 0 {
			break
		}
		if l > 63 {
			return nil
		}
		i += l
	}
	if i+4 > len(query) {
		return nil
	}
	qtype := int(query[i])<<8 | int(query[i+1])
	i += 4
	resp := make([]byte, 12)
	copy(resp, query[:2])
	resp[2] = 0x81 // QR|RD
	resp[3] = 0x80 // RA, RCODE=0
	if qtype == 1 {
		resp[7] = 1 // ANCOUNT=1
	}
	resp = append(resp, query[12:i]...)
	if qtype == 1 {
		resp = append(resp, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 10, 0, 0, 3)
	}
	return resp
}

// resolveRealIP: реальный адрес dzen через ВНЕШНЮЮ цепочку resolveDNS
// (DoT/DoH/UDP), НЕ через наш UDP-DNS (иначе ответили бы 10.0.0.3).
func resolveRealIP(host string) (string, error) {
	q := make([]byte, 0, 64)
	q = append(q, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	for _, part := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		q = append(q, byte(len(part)))
		q = append(q, part...)
	}
	q = append(q, 0, 0, 1, 0, 1)
	ans, err := resolveDNS(q)
	if err != nil {
		return "", err
	}
	return firstAFromDNS(ans)
}

func firstAFromDNS(ans []byte) (string, error) {
	if len(ans) < 12 {
		return "", fmt.Errorf("short dns answer")
	}
	i := 12
	skipName := func() {
		for i < len(ans) {
			l := int(ans[i])
			if l == 0 {
				i++
				return
			}
			if l&0xC0 == 0xC0 {
				i += 2
				return
			}
			i += 1 + l
		}
	}
	qd := int(ans[4])<<8 | int(ans[5])
	for k := 0; k < qd; k++ {
		skipName()
		i += 4
	}
	an := int(ans[6])<<8 | int(ans[7])
	for k := 0; k < an && i+10 <= len(ans); k++ {
		skipName()
		if i+10 > len(ans) {
			break
		}
		typ := int(ans[i])<<8 | int(ans[i+1])
		rdlen := int(ans[i+8])<<8 | int(ans[i+9])
		i += 10
		if typ == 1 && rdlen == 4 && i+4 <= len(ans) {
			return fmt.Sprintf("%d.%d.%d.%d", ans[i], ans[i+1], ans[i+2], ans[i+3]), nil
		}
		i += rdlen
	}
	return "", fmt.Errorf("no A record")
}

// metaCSPRe - ленивая инициализация regex для meta CSP (229)
var metaCSPRe *regexp.Regexp

// DzenAdMarkerRe — маркер рекламы в тексте карточек Дзена (верхний баннер
// "реклама · 16+"). Одна логика с JS-боди (dzenCosmeticJS.ADL): selfcheck
// (mitm/selfcheck) при сборке гарантирует, что оба варианта принимают одни
// и те же строки.
var DzenAdMarkerRe = regexp.MustCompile(`(?i)^(?:реклама|соцреклама)(?:\s*[·•|—-]?\s*\d+\+)?$`)

// DzenAdDisclosureRe — сильный disclosure-маркер (234). JS ADD синхронизирован
// selfcheck'ом при сборке.
var DzenAdDisclosureRe = regexp.MustCompile(`(?i)^рекламное\s+объявление$`)

var dzenCosmeticJS = `(function(){
var sels='[data-ad-type="direct"],[data-ad-type="banner"],[data-ad-type="rtb"],.card-rtb,[class*="adBox"],[class*="MyTargetAdvert"],[class*="advertItem"],[data-testid="bottom-ad"],div[class*="topContent"][class*="mobile__hasBanner"],div[class*="news"] > div[class*="_banner_"],.zenad-card-rtb,.news-mt-advert,.mg-advert > div[class*="loader"],div[class*="Advert_"],div[class^="BrandingAdvert"],.news-advert-column,.article-render-mobile__embed_embed-type_yandex-direct,div[class^="dzen-desktop--banner-"],div[class*="-corner-banner__"],div[class^="content--dzen-pro-"],div[class^="dzen-mobile__bannerMain-"]';
var ADL=/^(?:реклама|соцреклама)(?:\s*[·•|—-]?\s*\d+\+)?$/i;
// 234: сильный disclosure-маркер. JS ADD и Go DzenAdDisclosureRe синхронизированы
// selfcheck'ом при сборке.
var ADD=/^рекламное\s+объявление$/i;
function isAdMarker(v){return ADL.test(v)||ADD.test(v);}
var diagSent=0,iframeSent=0,iframeSeen={},shadowSeen=[],shadowCount=0;
function beacon(data){
  try{ if(navigator.sendBeacon && navigator.sendBeacon('/__configadblock_diag?d='+encodeURIComponent(data),new Blob([]))) return; }catch(_){}
  try{ fetch('/__configadblock_diag?d='+encodeURIComponent(data),{method:'GET',cache:'no-store',credentials:'omit'}).catch(function(){}); }catch(_){}
}
function sendDiag(sig){if(!sig||sig.length>1000)return;if(diagSent>=8&&sig.indexOf('CAROUSEL_CANDIDATE')<0&&sig.indexOf('CAROUSEL_AD_FOUND')<0&&sig.indexOf('DISCLOSURE_CANDIDATE')<0&&sig.indexOf('AD_DISCLOSURE_FOUND')<0&&sig.indexOf('FEED_AD_RULE_MATCH')<0&&sig.indexOf('FEED_PROBE')<0&&sig.indexOf('FEED_CAROUSEL_MARKER')<0&&sig.indexOf('APP_WRAPPER_CANDIDATE')<0&&sig.indexOf('APP_INNER_FALLBACK')<0&&sig.indexOf('ORPHAN_MEDIA_CLEANED')<0)return;diagSent++;beacon(sig);}
function sendIframe(host){if(iframeSent>=10||!host||host.length>80||iframeSeen[host])return;iframeSeen[host]=1;iframeSent++;beacon('IFRAME host='+host);}
function marker(e){beacon(e);}
function norm(s){return (s||'').replace(/ /g,' ').replace(/\s+/g,' ').trim();}
function rect(e){try{var r=e.getBoundingClientRect();return 'x='+Math.round(r.left)+' y='+Math.round(r.top)+' w='+Math.round(r.width)+' h='+Math.round(r.height);}catch(_){return '';}}
function sigOf(e,levels){
  var parts=[],n=e;
  for(var k=0;k<(levels||10)&&n;k++){
    var s=n.tagName||'';
    if(n.id)s+='#'+n.id;
    var c=(n.className&&n.className.toString)?n.className.toString():'';
    if(c)s+='.'+c.split(' ').slice(0,3).join('.');
    if(s.length>60)s=s.slice(0,60);
    s+=' '+rect(n);
    parts.push('P'+k+' '+s);
    n=n.parentElement;
  }
  return parts.join(' | ');
}
function rmSel(root){
  if(!root.querySelectorAll)return;
  if(root.matches&&root.matches(sels))root.remove();
  root.querySelectorAll(sels).forEach(function(e){e.remove();});
}
function hasT(root,t){return (root.textContent||'').indexOf(t)>=0;}
// 232: slides могут быть grandchildren (wrapper > track > slide).
// 234: combo detection — добавленный subtree содержит disclosure+скрыть+пожаловаться
// (textContent объединяет разбитые по span строки). Только маленькие subtree.
function comboDisclosure(nd){
  try{
    if(!nd||nd.nodeType!==1)return;
    var t=nd.textContent||'';
    if(t.length<4000&&t.indexOf('Рекламное объявление')>=0&&t.indexOf('Скрыть объявление')>=0&&t.indexOf('Пожаловаться')>=0){
      sendDiag('DISCLOSURE_COMBO len='+t.length);
      handleDisclosure(nd,'рекламное объявление');
    }
  }catch(_){}
}
// 234: STRONG_AD_DISCLOSURE. "Рекламное объявление" + меню рядом (>=2 фраз) —
// якорь для удаления ВСЕЙ карусели, а не только панели disclosure.
// Wrapper: самый внешний ancestor (до 12), который содержит disclosure-текст,
// pager>=2, largeMedia>=1 или media, height<=80% vh, не захватывает next post.
function handleDisclosure(el,mt){
  if(!el)return;
  sendDiag('DISCLOSURE='+mt+' :: '+sigOf(el,6));
  var phrases=['Скрыть объявление','Пожаловаться','О рекламодателе','Реклама на Яндексе'];
  var host=null,hits=0,n=el;
  for(var p=0;p<12&&n&&n.parentElement;p++){
    n=n.parentElement;
    var t=(n.textContent||'');
    var c=0;
    for(var q=0;q<phrases.length;q++){if(t.indexOf(phrases[q])>=0)c++;}
    if(c>=2){host=n;hits=c;break;}
  }
  if(hits>=2)sendDiag('AD_DISCLOSURE_FOUND phrases='+hits);
  var anchor=host||el;
  if(!host){
    try{
      var t2=(anchor.textContent||'');
      if(t2.indexOf('Рекламное объявление')>=0&&t2.indexOf('Скрыть объявление')>=0&&t2.indexOf('Пожаловаться')>=0){hits=3;sendDiag('AD_DISCLOSURE_FOUND combo=1');}
    }catch(_){}
  }
  var chain=[],m=anchor;
  for(var up=0;up<12&&m&&m.parentElement;up++){m=m.parentElement;chain.push(m);}
  var car=null,ciInfo=null;
  for(var i=0;i<chain.length;i++){
    var a=chain[i];
    try{if((a.textContent||'').indexOf('Рекламное объявление')<0)continue;}catch(_){continue;}
    var pg=findPager(a);
    if(!pg.found||pg.count<2)continue;
    var lm=countLargeMedia(a);
    var media=0;
    try{media=a.querySelectorAll('img,video,[class*="card-rtb"],[class*="adBox"]').length;}catch(_){}
    if(lm<1&&media<1)continue;
    var r=a.getBoundingClientRect();
    if(r&&r.height>window.innerHeight*0.8)continue;
    var news=0;
    try{news=a.querySelectorAll('article,[role="article"]').length;}catch(_){}
    if(news>1)continue;
    ciInfo='pager='+pg.count+' largeMedia='+lm+' rect='+(r?Math.round(r.width)+'x'+Math.round(r.height):'?');
    sendDiag('DISCLOSURE_CANDIDATE '+ciInfo+' :: '+sigOf(a,4));
    car=a;
  }
  if(car){
    marker('DISCCAR');
    var dcp=car.parentElement;
    car.remove();
    marker('DISCCAR_RM');
    cleanupAdOrphan(dcp);
    return;
  }
  // disclosure есть, карусель по пагеру/media не подтвердилась —
  // отрабатываем как обычный ad marker
  try{handleMarker(anchor,mt);}catch(_){}
}
// 238: локальная очистка orphan-media ПОСЛЕ подтверждённого ad-remove.
// Только бывший parent, его children и до 3 ancestors — НИКАКОГО document scan.
// Candidate: нет article/role=article, нет «Подписаться»/«комментар», текст
// после trim короткий (<80), есть крупный media (>=70% viewport и >=150px).
// Pager/dots внутри candidate уходят вместе с ним. Защита обычных постов:
// заголовок/автор/кнопки дают длинный текст или article — candidate skipped.
function cleanupAdOrphan(start){
  try{
    if(!start||!start.querySelectorAll)return;
    var vw=window.innerWidth;
    var nodes=[];
    nodes.push(start);
    try{for(var s=0;s<start.children.length;s++)nodes.push(start.children[s]);}catch(_){}
    var p=start;
    for(var a=0;a<3&&p&&p.parentElement;a++){
      p=p.parentElement;
      var tg=(p.tagName||'').toUpperCase();
      if(tg==='BODY'||tg==='HTML')break;
      nodes.push(p);
    }
    for(var i=0;i<nodes.length;i++){
      var n=nodes[i];
      if(!n||!n.isConnected||!n.querySelectorAll)continue;
      var tag=(n.tagName||'').toUpperCase();
      if(tag==='BODY'||tag==='HTML')continue;
      if(n.querySelector('article,[role="article"]'))continue;
      var txt=(n.textContent||'').replace(/\s+/g,' ').trim();
      if(txt.indexOf('Подписаться')>=0||txt.indexOf('комментар')>=0)continue;
      if(txt.length>=80)continue;
      var media=0;
      var els=n.querySelectorAll('img,picture,video,canvas,[style*="background-image"]');
      for(var m=0;m<els.length;m++){
        var r=els[m].getBoundingClientRect();
        if(r&&r.width>=vw*0.7&&r.height>=150)media++;
      }
      if(media<1)continue;
      try{sendDiag('ORPHAN_MEDIA_CLEANED text='+txt.length+' media='+media);}catch(_){}
      n.remove();
      break;
    }
  }catch(_){}
}
// 237: сильная APP-сигнатура (Google Play app install ads).
function isAppAd(n){
  try{return hasT(n,'Рейтинг и отзывы')&&hasT(n,'О приложении')&&(hasT(n,'Реклама')||hasT(n,'реклама'));}catch(_){return false;}
}
// 237: outer APP wrapper из chain — самый внешний безопасный ancestor:
// width >=75% viewport, 220px <= height <= 70% vh, содержит APP marker,
// не BODY/HTML, <=1 обычная статья. Pager — только бонусный сигнал.
function findAppAdWrapper(el,chain){
  try{
    var vw=window.innerWidth,vh=window.innerHeight;
    var best=null;
    for(var i=0;i<chain.length;i++){
      var a=chain[i];
      var t=(a.tagName||'').toUpperCase();
      if(t==='BODY'||t==='HTML')continue;
      if(!isAppAd(a))continue;
      var r=a.getBoundingClientRect();
      if(!r||r.width<=0||r.height<=0)continue;
      if(r.width<vw*0.75)continue;
      if(r.height<220)continue;
      if(r.height>vh*0.7)continue;
      var news=0;
      try{news=a.querySelectorAll('article,[role="article"]').length;}catch(_){}
      if(news>1)continue;
      best=a;
    }
    return best;
  }catch(_){return null;}
}
// 233: геометрический pager — 2-6 точек 4..24px, в одну горизонтальную линию,
// близко друг к другу, родитель существенно меньше media block.
// Без class="dot". Scan ограничен первыми 400 candidates внутри root.
function findPager(root){
  try{
    if(!root||!root.querySelectorAll)return{found:false,count:0};
    var all=root.querySelectorAll('*');
    for(var i=0;i<all.length&&i<400;i++){
      var p=all[i];
      if(!p.children||p.children.length<2||p.children.length>6)continue;
      var dots=0,ok=true,baseTop=-1;
      for(var j=0;j<p.children.length&&ok;j++){
        var c=p.children[j];
        if(c.children&&c.children.length>0){ok=false;break;}
        var r=c.getBoundingClientRect();
        if(!r||r.width<4||r.width>24||r.height<4||r.height>24){ok=false;break;}
        if(baseTop<0)baseTop=r.top;
        else if(Math.abs(r.top-baseTop)>8){ok=false;break;}
        if(j>0){var pr=p.children[j-1].getBoundingClientRect();if(Math.abs(r.left-(pr.left+pr.width))>32){ok=false;break;}}
        dots++;
      }
      if(ok&&dots>=2){
        var pr2=p.getBoundingClientRect();
        var rootR=root.getBoundingClientRect?root.getBoundingClientRect():null;
        if(rootR&&rootR.width>0&&pr2.width>rootR.width*0.8)continue;
        return{found:true,count:dots};
      }
    }
    return{found:false,count:0};
  }catch(_){return{found:false,count:0};}
}
// 233: крупный media-сигнал — img/picture/video/canvas/div с background-image,
// width >=50% viewport и height >=120px.
function countLargeMedia(n){
  var cnt=0;
  try{
    var vw=window.innerWidth;
    var els=n.querySelectorAll('img,picture,video,canvas');
    for(var i=0;i<els.length;i++){var r=els[i].getBoundingClientRect();if(r&&r.width>=vw*0.5&&r.height>=120)cnt++;}
    var divs=n.querySelectorAll('[style*="background-image"]');
    for(var k=0;k<divs.length;k++){var r2=divs[k].getBoundingClientRect();if(r2&&r2.width>=vw*0.5&&r2.height>=120)cnt++;}
  }catch(_){}
  return cnt;
}
// 233: multi-signal carousel. Никаких обязательных class names.
// Подтверждение (marker уже найден выше по стеку):
//   pager>=2 AND largeMedia>=1
//   OR horizontal AND largeMedia>=1
//   OR slideLikes>=2 AND (pager OR media>=2)
function carouselInfo(n){
  if(!n||!n.querySelector)return null;
  var pager=findPager(n);
  var largeMedia=countLargeMedia(n);
  var media=0;
  try{media=n.querySelectorAll('img,video,[class*="card-rtb"],[class*="adBox"]').length;}catch(_){}
  var slideLikes=0;
  try{slideLikes=n.querySelectorAll('[class*="slide"],[class*="carousel"],[class*="swiper"],[class*="track"]').length;}catch(_){}
  var horiz=false;
  try{var cs=getComputedStyle(n);horiz=(cs.overflowX==='auto'||cs.overflowX==='scroll')&&n.scrollWidth>n.clientWidth+40;}catch(_){}
  var confirmed=(pager.found&&pager.count>=2&&largeMedia>=1)
    ||(horiz&&largeMedia>=1)
    ||(slideLikes>=2&&(pager.found||media>=2));
  if(!confirmed)return null;
  return{pager:pager.count,largeMedia:largeMedia,media:media,slideLikes:slideLikes,horiz:horiz,dots:pager.found};
}
// 233: Phase 1 — собрать chain ДО любых remove(). Carousel analysis по всей
// chain, удаляется самый внешний безопасный wrapper (pager+largeMedia,
// height <=80% vh, не захватывает следующий пост). Phase 2 — orphan-guard:
// inner card НЕ удаляется, если у ancestor pager>=2 и largeMedia>=1 —
// удаляется outer candidate. Phase 3 — обычный ad container + orphan-check
// бывшего parent. Phase 4 — topBannerCandidate (231, не менялся).
function handleMarker(el,mt){
  if(!el)return;
  sendDiag('MARKER='+mt+' :: '+sigOf(el,6));
  // 236: nearest .feed__item fallback ПЕРВЫМ — до любого remove внутри chain.
  // Внутри того же .feed__item уже найден точный AD marker: pager>=2 +
  // largeMedia>=1 => весь feed item удаляется целиком, не inner card.
  try{
    var feed=el.closest?el.closest('.feed__item'):null;
    if(feed){
      var sv=false;
      try{sv=feed.matches(':has(> div.short-video-carousel-view)');}catch(_){sv=false;}
      if(!sv){
        var fpg=findPager(feed);
        var flm=countLargeMedia(feed);
        if(fpg.found&&fpg.count>=2&&flm>=1){
          var fr=feed.getBoundingClientRect();
          var fnm=mt.replace(/\s+/g,'_').replace(/[·•|—-]/g,'_').slice(0,20);
          sendDiag('FEED_CAROUSEL_MARKER marker='+fnm+' pager='+fpg.count+' largeMedia='+flm+' rect='+Math.round(fr.width)+'x'+Math.round(fr.height));
          var fp=feed.parentElement;
          feed.remove();
          marker('FEEDCAR_RM');
          cleanupAdOrphan(fp);
          return;
        }
      }
    }
  }catch(_){}
  var chain=[],n=el;
  for(var up=0;up<14&&n&&n.parentElement;up++){n=n.parentElement;chain.push(n);}
  var car=null,ciBest=null;
  for(var i=0;i<chain.length;i++){
    var ci=carouselInfo(chain[i]);
    if(!ci)continue;
    var r=chain[i].getBoundingClientRect();
    if(r&&r.height>window.innerHeight*0.8)continue;
    var news=0;
    try{news=chain[i].querySelectorAll('article,[role="article"]').length;}catch(_){}
    if(news>1)continue;
    ciBest=ci;car=chain[i];
  }
  if(car){
    var cinfo='pager='+ciBest.pager+' largeMedia='+ciBest.largeMedia+' media='+ciBest.media+' slideLikes='+ciBest.slideLikes+' horizontal='+ciBest.horiz;
    try{var rr=car.getBoundingClientRect();cinfo+=' rect='+Math.round(rr.width)+'x'+Math.round(rr.height);}catch(_){}
    sendDiag('CAROUSEL_CANDIDATE '+cinfo+' :: '+sigOf(car,4));
    sendDiag('CAROUSEL_AD_FOUND '+cinfo);
    marker('CAROUSEL');
    var carp=car.parentElement;
    car.remove();
    marker('CARWRAPPER');
    cleanupAdOrphan(carp);
    return;
  }
  for(var j=0;j<chain.length;j++){
    n=chain[j];
    var pg=findPager(n);
    var lm=countLargeMedia(n);
    if(pg.found&&pg.count>=2&&lm>=1){
      var oi='pager='+pg.count+' largeMedia='+lm;
      try{var or2=n.getBoundingClientRect();oi+=' rect='+Math.round(or2.width)+'x'+Math.round(or2.height);}catch(_){}
      sendDiag('CAROUSEL_CANDIDATE orphan-guard '+oi+' :: '+sigOf(n,4));
      marker('CAROUSEL');
      var ogp=n.parentElement;
      n.remove();
      marker('CARWRAPPER');
      cleanupAdOrphan(ogp);
      return;
    }
  }
  // 237: APP-ad (Google Play) — удаляется OUTER wrapper целиком (~340x358),
  // а не первый inner ancestor (~340x156). Сильная текстовая сигнатура +
  // геометрия + ограничение по article. Хешированные классы НЕ используются.
  var appHit=false;
  for(var ai=0;ai<chain.length;ai++){if(isAppAd(chain[ai])){appHit=true;break;}}
  if(appHit){
    var aw=findAppAdWrapper(el,chain);
    if(aw){
      var ir=el.getBoundingClientRect();
      var orr=aw.getBoundingClientRect();
      var apg=findPager(aw);
      try{sendDiag('APP_WRAPPER_CANDIDATE inner='+Math.round(ir.width)+'x'+Math.round(ir.height)+' outer='+Math.round(orr.width)+'x'+Math.round(orr.height)+' pager='+(apg.found?apg.count:0)+' :: '+sigOf(aw,4));}catch(_){}
      var appw=aw.parentElement;
      aw.remove();
      marker('APPW_RM');
      cleanupAdOrphan(appw);
      return;
    }
    sendDiag('APP_INNER_FALLBACK');
  }
  for(var j2=0;j2<chain.length;j2++){
    n=chain[j2];
    var s=((n.className&&n.className.toString)?n.className.toString():'')+' '+((n.id)||'');
    var cls=/advert|advertising|banner|adbox|rtb|zenad|brandingadvert/i.test(s);
    var triple=hasT(n,'Реклама')&&hasT(n,'Скрыть')&&hasT(n,'Пожаловаться');
    var app=hasT(n,'Рейтинг и отзывы')&&hasT(n,'О приложении')&&(hasT(n,'Реклама')||hasT(n,'реклама'));
    if(app){sendDiag('APP :: '+sigOf(n,4));marker('APPAD');} // 237: достижимо только если findAppAdWrapper не нашёл outer
    if(cls||triple||app){
      var parent=n.parentElement;
      n.remove();
      try{
        if(parent&&parent.querySelector){
          var txt=(parent.textContent||'').replace(/\s+/g,' ').trim();
          var pg2=findPager(parent);
          var lm2=countLargeMedia(parent);
          if(pg2.found&&pg2.count>=2&&lm2>=1&&txt.length<40){
            var op2=parent.parentElement;
            parent.remove();
            marker('ORPHANCAR');
            cleanupAdOrphan(op2);
          }
        }
      }catch(_){}
      return;
    }
  }
  var cand=topBannerCandidate(el);
  if(cand){
    try{
      var cr=cand.getBoundingClientRect();
      var nm=mt.replace(/\s+/g,'_').replace(/[·•|—-]/g,'_').slice(0,20);
      sendDiag('TOPBANNER_CANDIDATE marker='+nm+' rect='+Math.round(cr.width)+'x'+Math.round(cr.height)+' :: '+sigOf(cand,4));
    }catch(_){}
    marker('TOPBANNER');
    cand.remove();
  }
}
// 231: geometry-based top-banner selection. Без sib<=3: подъём максимум на 8
// ancestors, candidate = самый ВНЕШНИЙ узел, который ещё похож на отдельную
// рекламную карточку: ширина >=60% viewport, 40px<=высота<=35% viewport,
// не BODY/HTML, rect>0, не содержит несколько обычных новостных карточек.
// Высота <=35% vh гарантирует, что блок новостей ниже не захватывается.
function topBannerCandidate(el){
  try{
    var vw=window.innerWidth,vh=window.innerHeight;
    var best=null;
    var n=el;
    for(var up=0;up<8&&n&&n.parentElement;up++){
      n=n.parentElement;
      var t=(n.tagName||'').toUpperCase();
      if(t==='BODY'||t==='HTML')continue;
      var r=n.getBoundingClientRect();
      if(!r||r.width<=0||r.height<=0)continue;
      if(r.width<vw*0.6)continue;
      if(r.height<40)continue;
      if(r.height>vh*0.35)continue;
      var news=0;
      try{news=n.querySelectorAll('article,[role="article"]').length;}catch(_){}
      if(news>1)continue;
      best=n;
    }
    return best;
  }catch(_){return null;}
}
function eachText(root,cb){
  var doc=null;
  try{doc=(root.nodeType===9)?root:root.ownerDocument;}catch(_){}
  if(!doc||!doc.createTreeWalker||!root.nodeType)return;
  try{
    var w=doc.createTreeWalker(root,NodeFilter.SHOW_TEXT,null);
    var n;
    while((n=w.nextNode())){cb(n);}
  }catch(_){}
}
function scanText(root){
  eachText(root,function(tn){
    var v=norm(tn.nodeValue);
    if(!v)return;
    if(ADD.test(v)){
      try{beacon('DISCLOSURE '+v.replace(/\s+/g,'_').slice(0,20));}catch(_){}
      try{handleDisclosure(tn.parentElement,v);}catch(_){}
      return;
    }
    if(!ADL.test(v))return;
    try{beacon('ADMARKER '+v.replace(/\s+/g,'_').replace(/[·•|—-]/g,'_').slice(0,20));}catch(_){}
    try{handleMarker(tn.parentElement,v);}catch(_){}
  });
}
function emptyAdWrap(root){
  if(!root.querySelectorAll)return;
  root.querySelectorAll('div').forEach(function(d){
    var s=((d.className&&d.className.toString)?d.className.toString():'')+' '+(d.id||'');
    if(!/advert|banner|adbox|rtb|zenad|loader|skeleton/i.test(s))return;
    if((d.textContent||'').trim()!=='')return;
    if(d.querySelector('img,video,article,[role="article"]'))return;
    d.remove();
  });
}
function scanIframes(root){
  if(!root.querySelectorAll)return;
  root.querySelectorAll('iframe').forEach(function(f){
    var h='';
    try{var u=new URL(f.src||'',location.href);h=u.hostname||'';}catch(_){}
    if(h)sendIframe(h);
    try{var doc=f.contentDocument;if(doc&&doc.documentElement)scan(doc.documentElement);}catch(_){}
  });
}
function scanShadows(root){
  if(!root.querySelectorAll)return;
  root.querySelectorAll('*').forEach(function(e){
    if(shadowCount>=20)return;
    var sr=null;
    try{sr=e.shadowRoot;}catch(_){}
    if(sr){
      var key=sigOf(e,2);
      if(shadowSeen.indexOf(key)<0){
        shadowSeen.push(key);shadowCount++;
        scan(sr);
        try{
          var sobs=new MutationObserver(function(ms){ms.forEach(function(m){if(m.addedNodes)m.addedNodes.forEach(function(nd){if(nd.nodeType===1){scan(nd);comboDisclosure(nd);}else if(nd.nodeType===3){var sv=norm(nd.nodeValue);if(ADD.test(sv))handleDisclosure(nd.parentElement,sv);else if(ADL.test(sv))handleMarker(nd.parentElement,sv);}});});});
          sobs.observe(sr,{childList:true,subtree:true});
        }catch(_){}
      }
    }
  });
}
// 235: точный публичный AdGuard feed-ad selector для dzen.ru.
// Исключение :not(:has(> div.short-video-carousel-view)) ОБЯЗАТЕЛЬНО —
// защищает обычные short-video карусели. Не упрощать!
var FEEDAD='.feed__item article[class*="_is"]:not([class*="__card"]):not(:has(> div.short-video-carousel-view))';
// Диагностический поиск ДО удаления: MATCH -> remove -> REMOVED.
// Хешированные class names НЕ используем — только стабильная структура .feed__item.
function scanFeedAds(root){
  try{
    if(!root||!root.querySelectorAll)return;
    var cands=[];
    try{if(root.matches&&root.matches(FEEDAD))cands.push(root);}catch(_){}
    var all=root.querySelectorAll(FEEDAD);
    for(var i=0;i<all.length;i++)cands.push(all[i]);
    for(var k=0;k<cands.length;k++){
      var a=cands[k];
      if(!a||!a.isConnected)continue;
      var r=a.getBoundingClientRect();
      var pg=findPager(a.parentElement||a);
      var lm=countLargeMedia(a);
      sendDiag('FEED_AD_RULE_MATCH rect='+Math.round(r.width)+'x'+Math.round(r.height)+' hasPager='+pg.found+' largeMedia='+lm+' :: '+sigOf(a,3));
      var fap=a.parentElement;
      a.remove();
      marker('FEEDADRM');
      cleanupAdOrphan(fap);
    }
  }catch(_){}
}
function scan(root){
  try{
    if(root.nodeType===3){var v=norm(root.nodeValue);if(ADD.test(v))handleDisclosure(root.parentElement,v);else if(ADL.test(v))handleMarker(root.parentElement,v);return;}
    scanText(root);comboDisclosure(root);scanFeedAds(root);rmSel(root);emptyAdWrap(root);scanIframes(root);scanShadows(root);
  }catch(_){}
}
marker('JSALIVE238');
// 236: однократный probe структуры страницы — показывает, совпадает ли
// AdGuard FEEDAD selector с нынешней мобильной вёрсткой Dzen вообще.
var probed=false;
function feedProbe(){
  try{
    if(probed)return;probed=true;
    var feeds=document.querySelectorAll('.feed__item').length;
    var arts=document.querySelectorAll('.feed__item article[class*="_is"]').length;
    var exact=0;
    try{exact=document.querySelectorAll(FEEDAD).length;}catch(_){}
    sendDiag('FEED_PROBE feedItems='+feeds+' articles='+arts+' exactFeedAdMatches='+exact);
  }catch(_){}
}
scan(document);feedProbe();
[0,250,750,1500,3000,5000].forEach(function(t){setTimeout(function(){scan(document);},t);});
new MutationObserver(function(ms){
  ms.forEach(function(m){
    if(!m.addedNodes)return;
    m.addedNodes.forEach(function(nd){scan(nd);comboDisclosure(nd);});
  });
}).observe(document.documentElement,{childList:true,subtree:true});
})();`

// dzenInjectCSS внедряет external script/css (229): <script src="/__configadblock.js">
// и <link href="/__configadblock.css"> обслуживаются ЛОКАЛЬНО нашим MITM -
// inline JS убран, чтобы не путать диагностику доставки.
func dzenInjectCSS(html string) string {
	style := "<style data-cablock>\n" + dzenCSS + "</style>"
	assets := "<link rel=\"stylesheet\" href=\"/__configadblock.css\">\n" +
		"<script defer src=\"/__configadblock.js\"></script>"
	low := strings.ToLower(html)
	idx := strings.Index(low, "</head>")
	if idx > 0 {
		return html[:idx] + style + "\n" + assets + "\n" + html[idx:]
	}
	return style + "\n" + assets + "\n" + html
}

// handleDzenMITM — mini-MITM ТОЛЬКО для dzen.ru.
// handleDzenMITM - собственный selective content-MITM для dzen (2.0.7/209).
// Вызывается из SOCKS5 с УЖЕ прочитанным raw ClientHello - replay через
// sniffConn. Fail-open: отказ от сертификата/любая TLS-ошибка -> sni в
// bypassCache, следующий reconnect этого sni идёт DIRECT. Никакого goproxy.
func handleDzenMITM(conn net.Conn, sni string, raw []byte) (handled bool, ok bool) {
	// 220: ONE-SHOT bypass - этот вызов разрешаем direct, следующий снова MITM
	if bypassConsumeOne(sni) {
		flowLog("DZEN_BYPASS_ONCE_CONSUMED sni=" + sni)
		return false, false
	}
	flowLog("DZEN_MITM_BEGIN host=" + sni)
	// Resolve the leaf before consuming/writing TLS or taking ownership.
	leaf, err := certForName(sni)
	if err != nil {
		flowLog("DZEN_CA_FAIL host=" + sni + " err=" + err.Error())
		flowLog("DZEN_BYPASS_DIRECT sni=" + sni)
		return false, false
	}
	flowLog("DZEN_CA_READY host=" + sni)
	// 2.0.12: фактическая диагностика цепочки ДО handshake
	dzenDiagChain(sni, leaf)
	handled = true
	defer func() {
		if r := recover(); r != nil {
			flowLog(fmt.Sprintf("DZEN_MITM_FAIL panic:%v", r))
		}
		// 218: БЕЗ blanket cacheBypass - ошибка одного соединения
		// (timeout/EOF/resolve/upstream) не отключает фильтр для sni.
		// В bypass попадаем ТОЛЬКО при реальном TLS trust rejection.
		_ = conn.Close()
	}()
	cfg := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{*leaf},
	}
	tlsConn := tls.Server(&sniffConn{Conn: conn, prefix: raw}, cfg)
	_ = tlsConn.SetDeadline(time.Now().Add(20 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		// 218: bypass ТОЛЬКО при реальном отказе браузера от сертификата.
		// timeout/EOF/abort после TLS-слёта - обычная ошибка соединения,
		// reconnect должен снова попытать MITM.
		es := err.Error()
		certReject := strings.Contains(es, "unknown certificate") ||
			strings.Contains(es, "bad certificate") ||
			strings.Contains(es, "certificate required") ||
			strings.Contains(es, "certificate verify failed")
		if certReject {
			// 220: НЕ session-wide bypass - только один следующий reconnect
			bypassOnceSet(sni)
			flowLog("DZEN_TLS_REJECT host=" + sni + " err=" + es)
			flowLog("DZEN_BYPASS_ONCE_SET sni=" + sni + " reason=tls_reject")
		} else {
			flowLog("DZEN_TLS_FAIL host=" + sni + " err=" + es)
		}
		return true, false
	}
	_ = tlsConn.SetDeadline(time.Now().Add(30 * time.Second))
	flowLog("DZEN_TLS_OK sni=" + sni)
	// 218: успешный TLS снимает возможный старый transient bypass этого sni
	unBypassHost(sni)

	br := bufio.NewReader(tlsConn)
	reqs := 0
	flowLog("DZEN_CONN_OPEN sni=" + sni)
	for {
		// 221: idle/preconnect timeout - НЕ ошибка MITM, а нормальное
		// закрытие speculative/preconnect-соединения. 8 с простоя.
		_ = tlsConn.SetDeadline(time.Now().Add(8 * time.Second))
		req, err := http.ReadRequest(br)
		if err != nil {
			var ne net.Error
			if errors.Is(err, io.EOF) || (errors.As(err, &ne) && ne.Timeout()) {
				flowLog(fmt.Sprintf("DZEN_CONN_IDLE_CLOSE sni=%s requests=%d", sni, reqs))
				return true, true // benign: не считается MITM-ошибкой
			}
			flowLog(fmt.Sprintf("DZEN_CONN_CLOSE sni=%s requests=%d reason=read:%v", sni, reqs, err))
			return true, reqs > 0
		}
		reqs++
		flowLog(fmt.Sprintf("DZEN_REQ n=%d method=%s path=%s", reqs, req.Method, req.URL.Path))

		// 229: локальные asset-endpoint'ы - сами обслуживаем наши JS/CSS
		if req.URL.Path == "/__configadblock.js" {
			flowLog("DZEN_JS_FILE_REQUEST ruleset=238")
			jb := []byte(dzenCosmeticJS)
			if bytes.HasPrefix(jb, []byte("<script")) || bytes.Contains(jb, []byte("</script>")) {
				flowLog("DZEN_JS_BODY_INVALID")
			} else {
				flowLog("DZEN_JS_BODY_OK ruleset=238")
			}
			jr := &http.Response{StatusCode: 200, Status: "200 OK", Proto: "HTTP/1.1",
				ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header),
				Body: io.NopCloser(bytes.NewReader(jb)), ContentLength: int64(len(jb)), Close: false, Request: req}
			jr.Header.Set("Content-Type", "application/javascript; charset=utf-8")
			jr.Header.Set("Cache-Control", "no-store")
			_ = jr.Write(tlsConn)
			continue
		}
		if req.URL.Path == "/__configadblock.css" {
			flowLog("DZEN_CSS_FILE_REQUEST ruleset=238")
			cb := []byte(dzenCSS)
			cr := &http.Response{StatusCode: 200, Status: "200 OK", Proto: "HTTP/1.1",
				ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header),
				Body: io.NopCloser(bytes.NewReader(cb)), ContentLength: int64(len(cb)), Close: false, Request: req}
			cr.Header.Set("Content-Type", "text/css; charset=utf-8")
			cr.Header.Set("Cache-Control", "no-store")
			_ = cr.Write(tlsConn)
			continue
		}
		// 225: локальный diag-endpoint - DOM-сигнатуры не уходят на dzen.ru
		if req.URL.Path == "/__configadblock_diag" {
			q := req.URL.Query().Get("d")
			if len(q) > 1000 {
				q = q[:1000]
			}
			switch {
			case q == "JSALIVE228":
				flowLog("DZEN_JS_ALIVE ruleset=238")
			case q == "JSALIVE229":
				flowLog("DZEN_JS_ALIVE ruleset=238")
			case q == "JSALIVE230":
				flowLog("DZEN_JS_ALIVE ruleset=238")
			case q == "JSALIVE231":
				flowLog("DZEN_JS_ALIVE ruleset=238")
			case q == "JSALIVE233":
				flowLog("DZEN_JS_ALIVE ruleset=238")
			case q == "JSALIVE234":
				flowLog("DZEN_JS_ALIVE ruleset=238")
			case q == "JSALIVE235":
				flowLog("DZEN_JS_ALIVE ruleset=238")
			case q == "JSALIVE236":
				flowLog("DZEN_JS_ALIVE ruleset=238")
			case q == "JSALIVE237":
				flowLog("DZEN_JS_ALIVE ruleset=238")
			case q == "JSALIVE238":
				flowLog("DZEN_JS_ALIVE ruleset=238")
			case strings.HasPrefix(q, "ADMARKER "):
				flowLog("DZEN_AD_MARKER_MATCH value=" + strings.TrimPrefix(q, "ADMARKER "))
			case strings.HasPrefix(q, "IFRAME host="):
				flowLog("DZEN_IFRAME_DIAG host=" + strings.TrimPrefix(q, "IFRAME host="))
			case q == "APPAD":
				flowLog("DZEN_APP_AD_REMOVED")
			case strings.HasPrefix(q, "CAROUSEL_CANDIDATE "):
				flowLog("DZEN_CAROUSEL_CANDIDATE " + strings.TrimPrefix(q, "CAROUSEL_CANDIDATE "))
			case strings.HasPrefix(q, "CAROUSEL_AD_FOUND "):
				flowLog("DZEN_CAROUSEL_AD_FOUND " + strings.TrimPrefix(q, "CAROUSEL_AD_FOUND "))
			case q == "CAROUSEL":
				flowLog("DZEN_CAROUSEL_AD_FOUND")
			case q == "CARWRAPPER":
				flowLog("DZEN_CAROUSEL_WRAPPER_REMOVED")
			case q == "ORPHANCAR":
				flowLog("DZEN_ORPHAN_CAROUSEL_REMOVED")
			case strings.HasPrefix(q, "DISCLOSURE_CANDIDATE "):
				flowLog("DZEN_DISCLOSURE_CANDIDATE " + strings.TrimPrefix(q, "DISCLOSURE_CANDIDATE "))
			case q == "AD_DISCLOSURE_FOUND":
				flowLog("DZEN_AD_DISCLOSURE_FOUND")
			case q == "DISCCAR":
				flowLog("DZEN_AD_DISCLOSURE_FOUND")
			case q == "DISCCAR_RM":
				flowLog("DZEN_DISCLOSURE_CAROUSEL_REMOVED")
			case strings.HasPrefix(q, "FEED_AD_RULE_MATCH "):
				flowLog("DZEN_FEED_AD_RULE_MATCH " + strings.TrimPrefix(q, "FEED_AD_RULE_MATCH "))
			case q == "FEEDADRM":
				flowLog("DZEN_FEED_AD_RULE_REMOVED")
			case strings.HasPrefix(q, "FEED_PROBE "):
				flowLog("DZEN_FEED_PROBE " + strings.TrimPrefix(q, "FEED_PROBE "))
			case strings.HasPrefix(q, "FEED_CAROUSEL_MARKER "):
				flowLog("DZEN_FEED_CAROUSEL_MARKER_FOUND " + strings.TrimPrefix(q, "FEED_CAROUSEL_MARKER "))
			case q == "FEEDCAR_RM":
				flowLog("DZEN_FEED_CAROUSEL_REMOVED")
			case strings.HasPrefix(q, "APP_WRAPPER_CANDIDATE "):
				flowLog("DZEN_APP_AD_WRAPPER_CANDIDATE " + strings.TrimPrefix(q, "APP_WRAPPER_CANDIDATE "))
			case q == "APPW_RM":
				flowLog("DZEN_APP_AD_WRAPPER_REMOVED")
			case strings.HasPrefix(q, "ORPHAN_MEDIA_CLEANED "):
				flowLog("DZEN_ORPHAN_MEDIA_CLEANED " + strings.TrimPrefix(q, "ORPHAN_MEDIA_CLEANED "))
			case strings.HasPrefix(q, "TOPBANNER_CANDIDATE "):
				flowLog("DZEN_TOP_BANNER_CANDIDATE " + strings.TrimPrefix(q, "TOPBANNER_CANDIDATE "))
			case q == "TOPBANNER":
				flowLog("DZEN_TOP_BANNER_REMOVED")
			case q != "":
				flowLog("DZEN_DOM_DIAG " + q)
			}
			dr := &http.Response{StatusCode: 204, Status: "204 No Content", Proto: "HTTP/1.1",
				ProtoMajor: 1, ProtoMinor: 1, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader("")), ContentLength: 0, Close: false, Request: req}
			_ = dr.Write(tlsConn)
			continue
		}
		// Route only the selective host authenticated by the client SNI.
		upstreamHost := sni
		if req.Host != "" && !strings.EqualFold(req.Host, sni) && !strings.EqualFold(req.Host, net.JoinHostPort(sni, "443")) {
			flowLog(fmt.Sprintf("DZEN_CONN_CLOSE sni=%s requests=%d reason=host-mismatch", sni, reqs))
			return true, reqs > 0
		}
		ip, err := resolveRealIP(upstreamHost)
		if err != nil {
			flowLog("DZEN_MITM_POST_TLS_FAIL sni=" + sni + " stage=resolve err=" + err.Error())
			continue // апстрим не рвёт клиентскую TLS-сессию
		}
		up, err := dialTCP(net.JoinHostPort(ip, "443"))
		if err != nil {
			flowLog("DZEN_MITM_POST_TLS_FAIL sni=" + sni + " stage=updial err=" + err.Error())
			continue
		}
		upTLS := tls.Client(up, &tls.Config{ServerName: upstreamHost, MinVersion: tls.VersionTLS12})
		_ = upTLS.SetDeadline(time.Now().Add(20 * time.Second))
		if err := upTLS.Handshake(); err != nil {
			_ = up.Close()
			flowLog("DZEN_MITM_POST_TLS_FAIL sni=" + sni + " stage=uptls err=" + err.Error())
			continue
		}
		_ = upTLS.SetDeadline(time.Now().Add(30 * time.Second))
		_ = tlsConn.SetDeadline(time.Now().Add(30 * time.Second))

		outReq := new(http.Request)
		*outReq = *req
		outReq.URL.Scheme = "https"
		outReq.URL.Host = upstreamHost
		outReq.RequestURI = ""
		outReq.Close = true // upstream открываем на каждый request - keep-alive не нужен
		outReq.Header = req.Header.Clone()
		outReq.Header.Del("Proxy-Connection")
		outReq.Header.Del("Accept-Encoding") // иначе br/gzip-тело не проинжектить
		if err := outReq.Write(upTLS); err != nil {
			_ = up.Close()
			flowLog("DZEN_MITM_POST_TLS_FAIL sni=" + sni + " reqwrite:" + err.Error())
			continue
		}
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		resp, err := http.ReadResponse(bufio.NewReader(upTLS), outReq)
		if err != nil {
			_ = up.Close()
			flowLog("DZEN_MITM_POST_TLS_FAIL sni=" + sni + " upread:" + err.Error())
			continue
		}
		flowLog(fmt.Sprintf("DZEN_RESP n=%d status=%s path=%s", reqs, resp.Status, req.URL.Path))
		flowLog(fmt.Sprintf("DZEN_RESPONSE host=%s method=%s path=%s status=%s ct=%s len=%d",
			upstreamHost, req.Method, req.URL.Path, resp.Status,
			strings.ToLower(resp.Header.Get("Content-Type")), resp.ContentLength))
		if err := filterDzenResponse(resp, req.URL.Path); err != nil {
			resp.Body.Close()
			_ = up.Close()
			flowLog("DZEN_MITM_POST_TLS_FAIL sni=" + sni + " body:" + err.Error())
			continue
		}
		// 221: клиентская TLS-сессия НЕ рвётся после каждого ответа
		resp.Close = false
		if err := resp.Write(tlsConn); err != nil {
			resp.Body.Close()
			_ = up.Close()
			flowLog(fmt.Sprintf("DZEN_CONN_CLOSE sni=%s requests=%d reason=respwrite:%v", sni, reqs, err))
			return true, reqs > 0
		}
		resp.Body.Close()
		_ = up.Close()
	}
}
// Keep the body reader consistent with any rewritten content and length.
func filterDzenResponse(resp *http.Response, reqPath string) error {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	// 216: для Дзена снимаем CSP - иначе inline <script> косметики заблокирован
	resp.Header.Del("Content-Security-Policy")
	resp.Header.Del("Content-Security-Policy-Report-Only")
	if strings.Contains(ct, "text/html") {
		flowLog("DZEN_HTML_RESPONSE path=" + reqPath + " enc=" + resp.Header.Get("Content-Encoding"))
	}
	if strings.Contains(ct, "text/html") && (resp.Header.Get("Content-Encoding") == "" || resp.Header.Get("Content-Encoding") == "identity") {
		const limit = 16 * 1024 * 1024
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return err
		}
		if len(body) <= limit {
			if metaCSPRe == nil {
				metaCSPRe = regexp.MustCompile(`(?i)<meta[^>]+http-equiv=["']content-security-policy["'][^>]*>`)
			}
			if metaCSPRe.Match(body) {
				flowLog("DZEN_META_CSP_FOUND")
				body = metaCSPRe.ReplaceAll(body, nil)
				flowLog("DZEN_META_CSP_REMOVED")
			}
			body = []byte(dzenInjectCSS(string(body)))
			flowLog("DZEN_COSMETIC_RULESET=238")
		flowLog("DZEN_COSMETIC_INJECTED path=" + reqPath + " ruleset=238")
			resp.Body = io.NopCloser(bytes.NewReader(body))
			resp.ContentLength = int64(len(body))
			resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
			resp.Header.Del("Transfer-Encoding")
			resp.Header.Del("Content-Security-Policy")
			resp.Header.Del("Content-Security-Policy-Report-Only")
			resp.Header.Del("ETag")
			resp.TransferEncoding = nil
			flowLog("DZEN_HTML_FILTERED bytes=" + strconv.Itoa(len(body)))
		} else {
			// Preserve large responses instead of silently truncating them.
			resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), resp.Body))
			flowLog("DZEN_HTML_SKIP oversized")
		}
	}

	// 2.0.13/215: JSON-фильтрация ленты Дзена (рекламные элементы
	// удаляются из массивов целиком -> пустых контейнеров не остаётся).
	// Fail-open: любая ошибка -> оригинальный body без изменений.
	// 217: структурная диагностика JSON (только ключи, без содержимого)
	if strings.Contains(ct, "application/json") && (resp.Header.Get("Content-Encoding") == "" || resp.Header.Get("Content-Encoding") == "identity") {
		if jb, jerr := io.ReadAll(io.LimitReader(resp.Body, 4*1024*1024)); jerr == nil {
			resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(jb), resp.Body))
			dzenDiagJSON(reqPath, jb)
		}
	}
	if strings.Contains(ct, "application/json") {
		const limit = 16 * 1024 * 1024
		body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return err
		}
		final := body
		if len(body) > limit {
			resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), resp.Body))
			flowLog("DZEN_JSON_SKIP oversized")
			return nil
		}
		enc := strings.ToLower(resp.Header.Get("Content-Encoding"))
		switch enc {
		case "", "identity":
			filtered, removed, ferr := dzenFilterJSON(body, reqPath)
			if ferr != nil {
				flowLog("DZEN_JSON_SKIP parse-fail")
			} else if removed > 0 {
				final = filtered
				flowLog(fmt.Sprintf("DZEN_JSON_FILTERED path=%s removed=%d", reqPath, removed))
			}
		case "gzip":
			raw, e1 := dzenGunzip(body)
			if e1 != nil {
				flowLog("DZEN_JSON_SKIP gunzip:" + e1.Error())
			} else {
				filtered, removed, ferr := dzenFilterJSON(raw, reqPath)
				switch {
				case ferr != nil:
					flowLog("DZEN_JSON_SKIP parse-fail")
				case removed == 0:
				default:
					if out, e2 := dzenGzip(filtered); e2 != nil {
						flowLog("DZEN_JSON_SKIP regzip:" + e2.Error())
					} else {
						final = out
						flowLog(fmt.Sprintf("DZEN_JSON_FILTERED path=%s removed=%d", reqPath, removed))
					}
				}
			}
		default:
			// br/deflate без поддержки - НЕ ломаем, отдаём как есть
			flowLog("DZEN_FILTER_SKIP encoding=" + enc)
		}
		resp.Body = io.NopCloser(bytes.NewReader(final))
		resp.ContentLength = int64(len(final))
		resp.Header.Set("Content-Length", strconv.Itoa(len(final)))
		resp.Header.Del("Transfer-Encoding")
		resp.TransferEncoding = nil
	}

	return nil
}


// dzenDiagChain - фактическая проверка TLS-цепочки Дзена ДО handshake:
// SAN, issuer, подпись ТЕКУЩИМ CA, EKU, срок + длина/хэши реально
// отправляемой цепочки. Ответ на вопрос "почему unknown certificate".
func dzenDiagChain(host string, cert *tls.Certificate) {
	chainLen := len(cert.Certificate)
	flowLog(fmt.Sprintf("DZEN_CHAIN_LEN=%d", chainLen))
	for i, der := range cert.Certificate {
		fp := sha256.Sum256(der)
		flowLog(fmt.Sprintf("DZEN_CHAIN_%d_SHA256=%X", i, fp[:8]))
	}
	if chainLen == 0 {
		flowLog("LEAF_HOST=" + host + " LEAF_MISSING=true")
		return
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		flowLog("LEAF_HOST=" + host + " LEAF_PARSE_FAIL=" + err.Error())
		return
	}
	sanOK := leaf.VerifyHostname(host) == nil
	cur := currentMITMCA()
	issuerMatch := cur != nil && leaf.Issuer.String() == cur.Subject.String()
	sigOK := false
	if cur != nil {
		sigOK = leaf.CheckSignatureFrom(cur) == nil
	}
	serverAuth := false
	for _, u := range leaf.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	now := time.Now()
	valid := now.After(leaf.NotBefore) && now.Before(leaf.NotAfter)
	flowLog(fmt.Sprintf("LEAF_HOST=%s SAN_OK=%v ISSUER_MATCH=%v SIG_OK=%v SERVER_AUTH=%v VALID=%v IsCA=%v",
		host, sanOK, issuerMatch, sigOK, serverAuth, valid, leaf.IsCA))
}


// --- 2.0.13/215: JSON-фильтрация Дзена -------------------------------------

var dzenAdKeyHints = []string{"advert", "banner", "adfox", "nativead", "promo",
	"commercial", "socialad", "yandexad", "zen_ad", "ad_type", "adtype", "isad", "advertisement"}

func dzenGunzip(b []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(io.LimitReader(zr, 64*1024*1024))
}

func dzenGzip(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// dzenFilterJSON парсит JSON, логирует найденные рекламные маркеры и
// удаляет рекламные элементы массивов. Возвращает nil,0,nil если нечего
// удалять. Любая ошибка -> оригинальный body (fail-open снаружи).
func dzenBoolFlag(m map[string]interface{}, key string) string {
	if m == nil {
		return "missing"
	}
	v, ok := m[key]
	if !ok {
		return "missing"
	}
	b, ok := v.(bool)
	if !ok {
		return "missing"
	}
	if b {
		return "true"
	}
	return "false"
}

func dzenCountElems(v interface{}) int {
	switch t := v.(type) {
	case []interface{}:
		return len(t)
	case map[string]interface{}:
		return len(t)
	}
	return 1
}

// dzenFilterMorePath - 219: точечная фильтрация /api/web/v1/more.
// Только здесь: top-level ad_items удаляется целиком, items[] выкидываются
// ТОЛЬКО при isNativeAds==true / isPromoPublication==true (не по наличию ключа).
func dzenFilterMorePath(root *interface{}, reqPath string) (removed int, adItemsRemoved int, cardsRemoved int) {
	if reqPath != "/api/web/v1/more" {
		return 0, 0, 0
	}
	m, ok := (*root).(map[string]interface{})
	if !ok {
		return 0, 0, 0
	}
	if ai, exists := m["ad_items"]; exists && !dzenEmptyVal(ai) {
		n := dzenCountElems(ai)
		delete(m, "ad_items")
		removed++
		adItemsRemoved = n
		flowLog(fmt.Sprintf("DZEN_JSON_FIELD_REMOVED path=%s key=ad_items count=%d", reqPath, n))
	}
	if arr, ok := m["items"].([]interface{}); ok {
		kept := arr[:0]
		for i, el := range arr {
			em, _ := el.(map[string]interface{})
			ina := dzenBoolFlag(em, "isNativeAds")
			ipp := dzenBoolFlag(em, "isPromoPublication")
			plEmpty := true
			if pl, ok2 := em["promoLabel"].(map[string]interface{}); ok2 {
				plEmpty = len(pl) == 0
			}
			flowLog(fmt.Sprintf("DZEN_ITEM_FLAGS index=%d isNativeAds=%s isPromoPublication=%s promoLabelEmpty=%v",
				i, ina, ipp, plEmpty))
			reason := ""
			if ina == "true" {
				reason = "isNativeAds=true"
			} else if ipp == "true" {
				reason = "isPromoPublication=true"
			}
			if reason != "" {
				cardsRemoved++
				removed++
				flowLog(fmt.Sprintf("DZEN_JSON_CARD_REMOVED path=.items[%d] reason=%s id=%s", i, reason, dzenElemID(em)))
				continue
			}
			kept = append(kept, el)
		}
		m["items"] = kept
	}
	return removed, adItemsRemoved, cardsRemoved
}

func dzenFilterJSON(body []byte, reqPath string) ([]byte, int, error) {
	var v interface{}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, 0, err
	}
	// 219: точечная обработка ленты Дзен
	mr, adN, cardN := dzenFilterMorePath(&v, reqPath)
	removed, markers := dzenScrub(&v, "")
	removed += mr
	if len(markers) == 0 {
		flowLog("DZEN_JSON_NO_AD_MARKERS")
	} else {
		seen := make(map[string]bool)
		n := 0
		for _, m := range markers {
			if !seen[m] && n < 12 {
				seen[m] = true
				n++
				flowLog("DZEN_JSON_AD_FOUND " + m)
			}
		}
	}
	if removed == 0 {
		return nil, 0, nil
	}
	out, err := json.Marshal(v)
	if err != nil {
		return nil, 0, err
	}
	if adN > 0 || cardN > 0 {
		flowLog(fmt.Sprintf("DZEN_FEED_FILTER path=%s adItemsRemoved=%d cardsRemoved=%d",
			reqPath, adN, cardN))
	}
	return out, removed, nil
}

func dzenIsAdKey(kl string) bool {
	for _, a := range dzenAdKeyHints {
		if kl == a || strings.Contains(kl, a) {
			return true
		}
	}
	return false
}

func dzenIsAdElement(m map[string]interface{}) bool {
	for k, v := range m {
		kl := strings.ToLower(k)
		switch kl {
		case "isad", "is_ad":
			if b, ok := v.(bool); ok && b {
				return true
			}
		case "adtype", "ad_type", "type":
			if s, ok := v.(string); ok && dzenAdTypeVal(s) {
				return true
			}
		case "adfox", "nativead", "native_ad", "zen_ad", "advertising", "advertisement":
			return true
		}
	}
	return false
}

func dzenAdTypeVal(s string) bool {
	s = strings.ToLower(s)
	return s == "ad" || strings.Contains(s, "direct") || strings.Contains(s, "banner") ||
		strings.Contains(s, "promo") || strings.Contains(s, "advert") || strings.Contains(s, "native")
}

func dzenElemID(m map[string]interface{}) string {
	for _, k := range []string{"id", "feedId", "documentId", "rid", "blockId"} {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				if len(s) > 16 {
					return s[:16]
				}
				return s
			}
		}
	}
	return "-"
}

// dzenContainsStrongAdSignal - СИЛЬНЫЕ рекламные признаки во всём subtree
// карточки (включая вложенные data/content/meta). Консервативно: generic
// "promo" и любое вхождение "ad" НЕ считаются рекламой.
func dzenContainsStrongAdSignal(v interface{}, path string) (bool, string, string) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			kl := strings.ToLower(k)
			p := path + "." + k
			switch kl {
			case "isad", "is_ad":
				if b, ok := val.(bool); ok && b {
					return true, kl + "=true", p
				}
			case "adtype", "ad_type":
				if s, ok := val.(string); ok && dzenStrongAdType(s) {
					return true, kl + "=" + s, p
				}
			case "adfox", "nativead", "native_ad", "advertisement", "advertising",
				"yandexad", "yandex_ad", "zen_ad", "direct":
				if !dzenEmptyVal(val) {
					return true, "key:" + kl, p
				}
			}
			if s, ok := val.(string); ok && dzenStrongAdLabel(s) {
				return true, "label:" + s, p
			}
			if hit, r, mp := dzenContainsStrongAdSignal(val, p); hit {
				return true, r, mp
			}
		}
	case []interface{}:
		for i, el := range t {
			if hit, r, mp := dzenContainsStrongAdSignal(el, fmt.Sprintf("%s[%d]", path, i)); hit {
				return true, r, mp
			}
		}
	case string:
		if dzenStrongAdLabel(t) {
			return true, "label:" + t, path
		}
	}
	return false, "", ""
}

func dzenStrongAdType(s string) bool {
	switch strings.ToLower(s) {
	case "ad", "direct", "banner", "advertising", "advertisement", "native", "nativead", "rtb":
		return true
	}
	return false
}

func dzenStrongAdLabel(s string) bool {
	sl := strings.ToLower(s)
	if strings.Contains(sl, "реклама") || strings.Contains(sl, "соцреклама") ||
		strings.Contains(sl, "advertisement") {
		return true
	}
	return false
}

func dzenEmptyVal(v interface{}) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return t == ""
	case bool:
		return !t
	case map[string]interface{}:
		return len(t) == 0
	case []interface{}:
		return len(t) == 0
	}
	return false
}

// dzenScrub: элементы массивов с СИЛЬНЫМ сигналом в любом месте subtree
// удаляются ЦЕЛИКОМ (контейнер схлопывается); очевидные рекламные поля в
// map удаляются отдельно. Маркеры в ключах логируются как раньше.
func dzenScrub(node *interface{}, path string) (int, []string) {
	removed := 0
	var markers []string
	switch t := (*node).(type) {
	case map[string]interface{}:
		for k, val := range t {
			kl := strings.ToLower(k)
			if dzenIsAdKey(kl) {
				markers = append(markers, fmt.Sprintf("key=%s path=%s type=%T", k, path+"."+k, val))
			}
			// отдельный очевидный рекламный payload-объект в map
			if dzenIsAdObjectKey(kl) && !dzenEmptyVal(val) {
				delete(t, k)
				removed++
				flowLog(fmt.Sprintf("DZEN_JSON_FIELD_REMOVED key=%s path=%s", k, path+"."+k))
				continue
			}
			r, m := dzenScrub(&val, path+"."+k)
			t[k] = val
			removed += r
			markers = append(markers, m...)
		}
	case []interface{}:
		kept := t[:0]
		for i, el := range t {
			// 216: СНАЧАЛА глубокая проверка ВСЕГО subtree карточки
			if hit, reason, mpath := dzenContainsStrongAdSignal(el, fmt.Sprintf("%s[%d]", path, i)); hit {
				removed++
				flowLog(fmt.Sprintf("DZEN_JSON_CARD_REMOVED path=%s[%d] reason=%s markerPath=%s id=%s",
					path, i, reason, mpath, dzenElemIDOf(el)))
				continue
			}
			var elv interface{} = el
			r, m := dzenScrub(&elv, fmt.Sprintf("%s[%d]", path, i))
			kept = append(kept, elv)
			removed += r
			markers = append(markers, m...)
		}
		*node = kept
	}
	return removed, markers
}

func dzenIsAdObjectKey(kl string) bool {
	switch kl {
	case "adfox", "nativead", "native_ad", "advertisement", "advertising",
		"yandexad", "yandex_ad", "zen_ad":
		return true
	}
	return false
}

func dzenElemIDOf(v interface{}) string {
	if m, ok := v.(map[string]interface{}); ok {
		return dzenElemID(m)
	}
	return "-"
}


// --- 2.0.15/217: структурная диагностика JSON (только ключи) ---------------

var dzenSuspectKeys = []string{"feed", "items", "cards", "publications", "recommendations",
	"content", "blocks", "stories", "entries", "documents", "zen", "rtb", "banner",
	"advert", "advertising", "native", "direct"}

// dzenDiagJSON логирует СТРУКТУРУ ответа: top-level ключи и объекты с
// подозрительными ключами. Ни одно значение не пишется - только имена ключей.
func dzenDiagJSON(reqPath string, body []byte) {
	var v interface{}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return
	}
	if m, ok := v.(map[string]interface{}); ok {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > 24 {
			keys = keys[:24]
		}
		flowLog("DZEN_JSON_KEYS path=" + reqPath + " keys=" + strings.Join(keys, ","))
	}
	dzenSuspectWalk(v, reqPath, reqPath, 0)
}

func dzenSuspectWalk(node interface{}, reqPath, jpath string, depth int) {
	if depth > 4 {
		return
	}
	switch t := node.(type) {
	case map[string]interface{}:
		var hits []string
		for k := range t {
			kl := strings.ToLower(k)
			for _, s := range dzenSuspectKeys {
				if kl == s || strings.Contains(kl, s) {
					hits = append(hits, k)
					break
				}
			}
		}
		if len(hits) > 0 {
			sort.Strings(hits)
			if len(hits) > 10 {
				hits = hits[:10]
			}
			flowLog("DZEN_JSON_SUSPECT path=" + reqPath + " jsonPath=" + jpath + " keys=" + strings.Join(hits, ","))
		}
		for k, val := range t {
			dzenSuspectWalk(val, reqPath, jpath+"."+k, depth+1)
		}
	case []interface{}:
		if len(t) > 3 {
			dzenSuspectWalk(t[0], reqPath, jpath+"[0]", depth+1)
		} else {
			for i, el := range t {
				dzenSuspectWalk(el, reqPath, fmt.Sprintf("%s[%d]", jpath, i), depth+1)
			}
		}
	}
}
