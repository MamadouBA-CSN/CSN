
(()=>{
'use strict';
try {
const $=id=>document.getElementById(id);
const CLE='CSN_1_4_HISTORIQUE';
const MAX_TEXT=2*1024*1024, MAX_SCAN=16*1024*1024, MAX_HASH=128*1024*1024, MAX_CDIR=8*1024*1024;
let dernierRapport=null;
let occupe=false;

function fmtSize(n){if(n<1024)return n+' o';if(n<1024**2)return (n/1024).toFixed(1)+' Ko';if(n<1024**3)return (n/1024**2).toFixed(1)+' Mo';return (n/1024**3).toFixed(2)+' Go'}
function extOf(name){const m=/\.([^.]+)$/.exec((name||'').toLowerCase());return m?m[1]:''}
function bytesToLatin1(bytes){let out='',step=0x8000;for(let i=0;i<bytes.length;i+=step)out+=String.fromCharCode.apply(null,bytes.subarray(i,Math.min(i+step,bytes.length)));return out}
function has(bytes,offset,arr){if(bytes.length<offset+arr.length)return false;for(let i=0;i<arr.length;i++)if(bytes[offset+i]!==arr[i])return false;return true}
function readU16LE(b,o){return (b[o]|(b[o+1]<<8))>>>0}
function readU32LE(b,o){return (b[o]|(b[o+1]<<8)|(b[o+2]<<16)|(b[o+3]<<24))>>>0}
function hex(buf){return [...new Uint8Array(buf)].map(x=>x.toString(16).padStart(2,'0')).join('')}
function loadHist(){try{const h=JSON.parse(localStorage.getItem(CLE)||'[]');return Array.isArray(h)?h.filter(x=>typeof x==='string').slice(-40):[]}catch(erreurIgnoree){return []}}
function saveHist(h){try{localStorage.setItem(CLE,JSON.stringify(h.slice(-40)))}catch(erreurIgnoree){}}
function addHist(line){const h=loadHist();h.push(new Date().toLocaleString()+' — '+line);saveHist(h);renderHist()}
function renderHist(){const h=loadHist();$('historique').textContent=h.length?h.slice().reverse().join('\n'):'Aucun événement enregistré.'}
function resumeSimple(level){
 if(level==='ÉLEVÉ')return 'Attention : des indices importants ont été repérés. Vérifiez avant d’agir.';
 if(level==='MODÉRÉ')return 'Prudence : certains points nécessitent une vérification.';
 return 'Aucun indice suspect repéré par les contrôles effectués. Cela ne garantit pas l’absence de danger.';
}
function setLevel(level){const e=$('niveau');e.textContent=level;e.className=level==='ÉLEVÉ'?'bad':level==='MODÉRÉ'?'warn':'ok'}
function maxLevel(a,b){const v={NORMAL:0,'MODÉRÉ':1,'ÉLEVÉ':2};return v[b]>v[a]?b:a}
function rules(level,obs,type,indices=[]){
 const message=['Message','Appel','IA'].includes(type), lien=type==='Lien';
 let decision,protection;
 if(level==='ÉLEVÉ'){
   decision=message?'Ne donnez aucun code, mot de passe ou paiement avant vérification.':lien?'N’ouvrez pas ce lien avant vérification.':'N’ouvrez pas, n’exécutez pas et n’installez pas ce fichier avant vérification.';
   protection=message?'Contactez l’expéditeur par un numéro ou une adresse que vous connaissez déjà. N’utilisez pas les coordonnées du message suspect.':lien?'Accédez au service par son application habituelle ou une adresse officielle déjà connue.':'Vérifiez la provenance du fichier. Faites-le examiner avec une solution de sécurité reconnue ou par un technicien de confiance. N’activez aucune macro.';
 }else if(level==='MODÉRÉ'){
   decision='Prenez le temps de vérifier les éléments signalés avant de poursuivre.';
   protection=message?'Confirmez l’identité de l’expéditeur et sa demande par un canal connu avant de répondre ou de payer.':lien?'Vérifiez le domaine de destination. Le site et ses redirections n’ont pas été visités.':'Vérifiez l’expéditeur, le contexte et les limites de l’inspection avant d’ouvrir ce fichier.';
 }else{
   decision='Aucun indice suspect détecté par ces contrôles. Ce résultat ne garantit pas l’absence de danger.';
   protection=message?'Vérifiez l’expéditeur et le contexte. Ne communiquez pas de code de vérification ou de mot de passe.':lien?'Vérifiez que cette adresse correspond au service attendu. HTTPS seul ne prouve pas sa fiabilité.':'Vérifiez la provenance du fichier avant utilisation. CSN ne certifie pas qu’il est sans danger.';
 }
 return {type,level,obs,indices,decision,protection};
}
function invaliderResultat(){
 dernierRapport=null;$('btnRapport').disabled=true;$('resumeSimple').textContent='Le contenu ou le mode a changé. Lancez un nouvel examen.';
 for(const id of ['typeDetecte','niveau','taille','hash']){$(id).textContent='—';$(id).className='muted'}
 $('observation').textContent='Le contenu a changé ou le mode a changé. Lancez un nouvel examen.';
 $('indices').textContent='Aucun résultat actuel.';$('decision').textContent='Examen nécessaire.';$('protection').textContent='—';
 $('etat').textContent='EXAMEN NÉCESSAIRE';$('etat').className='status warn';
}
function porteeRapport(r){
 if(r.type==='Appel')return 'Texte fourni uniquement ; appel non écouté, voix, numéro et identité non vérifiés. Règles principalement en français.';
 if(r.type==='IA')return 'Texte fourni et liens complets uniquement ; exactitude, sources, intentions et actions de l’IA non vérifiées. Règles principalement en français.';
 if(r.type==='Message')return 'Texte collé et 20 premiers liens HTTP(S) complets. Expéditeur, liens masqués et pièces jointes non vérifiés. Les règles de formulation sont principalement en français.';
 if(r.type==='Lien')return 'Adresse saisie uniquement. Site non visité ; redirections, réputation et contenu distant non vérifiés.';
 return 'Informations de base et indices selon le format. Lecture limitée à 16 Mo pour la structure, 2 Mo pour le texte et 8 Mo pour le répertoire ZIP (1 200 entrées maximum). Archives non décompressées ; flux PDF compressés non analysés. Empreinte calculée jusqu’à 128 Mo, si disponible : elle identifie les octets et ne prouve pas leur sécurité.';
}
function finish(result,file){
 $('typeDetecte').textContent=result.type;setLevel(result.level);$('resumeSimple').textContent=resumeSimple(result.level);
 $('observation').textContent=result.obs;
 $('indices').textContent=(result.indices && result.indices.length)?result.indices.map(x=>'• '+x).join('\n'):'Aucun indice technique inhabituel.';
 $('decision').textContent=result.decision;$('protection').textContent=result.protection;
 $('etat').textContent='INSPECTION TERMINÉE';$('etat').className='status '+(result.level==='ÉLEVÉ'?'bad':result.level==='MODÉRÉ'?'warn':'ok');
 dernierRapport={date:new Date().toLocaleString(),nom:file.name,taille:fmtSize(file.size),mime:file.type||'non déclaré',extension:extOf(file.name)||'(aucune)',type:result.type,niveau:result.level,hash:$('hash').textContent,observation:result.obs,indices:result.indices||[],decision:result.decision,protection:result.protection};
 $('btnRapport').disabled=false;
 addHist(`Inspection — ${file.name} — ${result.type} — ${result.level}`);
}
async function sha256(file){
 if(file.size>MAX_HASH)return 'Non calculée (fichier > 128 Mo)';
 try{if(!(window.crypto && window.crypto.subtle))return 'Indisponible sur ce navigateur';const ab=await file.arrayBuffer();return hex(await crypto.subtle.digest('SHA-256',ab));}
 catch(erreurIgnoree){return 'Indisponible sur ce navigateur'}
}
function sniff(bytes,ext,mime){
 if(has(bytes,0,[0x25,0x50,0x44,0x46,0x2d]))return 'PDF';
 if(has(bytes,0,[0x50,0x4b,0x03,0x04])||has(bytes,0,[0x50,0x4b,0x05,0x06])||has(bytes,0,[0x50,0x4b,0x07,0x08]))return 'ZIP';
 if(has(bytes,0,[0x4d,0x5a]))return 'PE/Windows';
 if(has(bytes,0,[0x7f,0x45,0x4c,0x46]))return 'ELF';
 if(has(bytes,0,[0xcf,0xfa,0xed,0xfe])||has(bytes,0,[0xce,0xfa,0xed,0xfe])||has(bytes,0,[0xfe,0xed,0xfa,0xcf])||has(bytes,0,[0xfe,0xed,0xfa,0xce])||has(bytes,0,[0xca,0xfe,0xba,0xbe]))return 'Mach-O';
 if(has(bytes,0,[0x00,0x61,0x73,0x6d]))return 'WebAssembly';
 if(has(bytes,0,[0x64,0x65,0x78,0x0a]))return 'DEX Android';
 if(has(bytes,0,[0xd0,0xcf,0x11,0xe0,0xa1,0xb1,0x1a,0xe1]))return 'OLE/Office ancien';
 if(has(bytes,0,[0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a]))return 'PNG';
 if(has(bytes,0,[0xff,0xd8,0xff]))return 'JPEG';
 if(has(bytes,0,[0x47,0x49,0x46,0x38]))return 'GIF';
 if(has(bytes,0,[0x52,0x61,0x72,0x21,0x1a,0x07]))return 'RAR';
 if(has(bytes,0,[0x37,0x7a,0xbc,0xaf,0x27,0x1c]))return '7Z';
 if(has(bytes,0,[0x49,0x44,0x33]))return 'MP3';
 if(bytes.length>12&&String.fromCharCode(...bytes.slice(4,8))==='ftyp')return 'MP4/ISO Media';
 if(bytes.length>12&&String.fromCharCode(...bytes.slice(0,4))==='RIFF')return 'RIFF';
 if(['docx','xlsx','pptx','docm','xlsm','pptm','odt','ods','odp','apk','zip','jar'].includes(ext))return 'ZIP';
 if((mime||'').startsWith('text/'))return 'Texte';
 return 'Inconnu';
}
function expectedMismatch(ext,sig){
 const map={pdf:['PDF'],png:['PNG'],jpg:['JPEG'],jpeg:['JPEG'],gif:['GIF'],zip:['ZIP'],docx:['ZIP'],xlsx:['ZIP'],pptx:['ZIP'],docm:['ZIP'],xlsm:['ZIP'],pptm:['ZIP'],apk:['ZIP'],jar:['ZIP'],exe:['PE/Windows'],dll:['PE/Windows']};
 return map[ext]&&!map[ext].includes(sig);
}
async function zipCentral(file){
 const tailLen=Math.min(file.size,131072);const tailStart=file.size-tailLen;
 const tail=new Uint8Array(await file.slice(tailStart).arrayBuffer());let e=-1;
 for(let i=tail.length-22;i>=0;i--){if(readU32LE(tail,i)===0x06054b50){e=i;break}}
 if(e<0)return {entries:[],warning:'Répertoire central ZIP non trouvé : inspection interne partielle.'};
 const total=readU16LE(tail,e+10),cdSize=readU32LE(tail,e+12),cdOff=readU32LE(tail,e+16);
 if(total===0xffff||cdSize===0xffffffff||cdOff===0xffffffff)return {entries:[],warning:'Archive ZIP64 : inspection interne limitée dans cette version.'};
 if(cdOff+cdSize>tailStart+e)return {entries:[],warning:'Répertoire ZIP incohérent : contenu interne non vérifié.'};
 const readSize=Math.min(cdSize,MAX_CDIR);const cd=new Uint8Array(await file.slice(cdOff,cdOff+readSize).arrayBuffer());
 const entries=[];let i=0;const td=new TextDecoder('utf-8',{fatal:false});
 while(i+46<=cd.length&&entries.length<1200){
   if(readU32LE(cd,i)!==0x02014b50){i++;continue}
   const flags=readU16LE(cd,i+8),method=readU16LE(cd,i+10),comp=readU32LE(cd,i+20),uncomp=readU32LE(cd,i+24),nl=readU16LE(cd,i+28),xl=readU16LE(cd,i+30),cl=readU16LE(cd,i+32);
   if(i+46+nl+xl+cl>cd.length)break;
   const raw=cd.subarray(i+46,i+46+nl);let name;
   try{name=(flags&0x800)?td.decode(raw):bytesToLatin1(raw)}catch(erreurIgnoree){name=bytesToLatin1(raw)}
   entries.push({name,flags,method,comp,uncomp});i+=46+nl+xl+cl;
 }
 return {entries,warning:cdSize>MAX_CDIR||entries.length!==total?'Répertoire ZIP inspecté partiellement ou incohérent : certains éléments n’ont pas été examinés.':null,totalDeclared:total};
}
function nameEnds(name,re){return re.test(name.toLowerCase())}
function pdfStructuralNames(raw){
 const names=new Set();const delimiter=c=>!c||/[\x00\x09\x0a\x0c\x0d\x20()<>\[\]{}\/%]/.test(c);
 for(let i=0;i<raw.length;){
  const c=raw[i];
  if(c==='%'){while(i<raw.length&&!/[\r\n]/.test(raw[i]))i++;continue;}
  if(c==='('){let depth=1;i++;while(i<raw.length&&depth){if(raw[i]==='\\'){i+=2;continue;}if(raw[i]==='(')depth++;if(raw[i]===')')depth--;i++;}continue;}
  if(c==='<'&&raw[i+1]!=='<'){const end=raw.indexOf('>',i+1);i=end<0?raw.length:end+1;continue;}
  if(c==='<'&&raw[i+1]==='<'){i+=2;continue;}
  if(raw.startsWith('stream',i)&&delimiter(raw[i-1])&&/[\r\n]/.test(raw[i+6]||'')){
   const end=raw.indexOf('endstream',i+6);i=end<0?raw.length:end+9;continue;
  }
  if(c==='/'){let j=i+1;while(j<raw.length&&!delimiter(raw[j]))j++;names.add(raw.slice(i+1,j).replace(/#([0-9a-fA-F]{2})/g,(_,h)=>String.fromCharCode(parseInt(h,16))));i=j;continue;}
  i++;
 }
 return names;
}
async function inspect(file){
 $('etat').textContent='INSPECTION EN COURS…';$('etat').className='status warn';$('taille').textContent=fmtSize(file.size);$('hash').textContent='Calcul…';$('btnRapport').disabled=true;dernierRapport=null;
 invaliderResultat();$('etat').textContent='INSPECTION EN COURS…';$('taille').textContent=fmtSize(file.size);
 const ext=extOf(file.name),mime=file.type||'';
 const head=new Uint8Array(await file.slice(0,Math.min(file.size,MAX_SCAN)).arrayBuffer());
 const sig=sniff(head,ext,mime);
 $('inspection').textContent=`${file.name}\nExtension : .${ext||'(aucune)'}\nType déclaré : ${mime||'non déclaré'}\nSignature détectée : ${sig}`;
 $('hash').textContent=await sha256(file);
 let mismatch=expectedMismatch(ext,sig);
 if(!file.size)return finish(rules('MODÉRÉ','Fichier vide : aucun contenu à examiner.','Fichier vide',['L’inspection du contenu n’a pas pu être effectuée.']),file);
 const execExt=['exe','dll','scr','msi','com','bat','cmd','ps1','vbs','vbe','js','jse','wsf','wsh','hta','reg','lnk','app','dmg','pkg','deb','rpm','sh','command','xpi','crx'];
 if(execExt.includes(ext)||['PE/Windows','ELF','Mach-O','WebAssembly','DEX Android'].includes(sig)){
   const ind=[`Fichier exécutable ou script (${ext||sig}) : il peut lancer du code.`];if(mismatch)ind.push('Extension et signature ne correspondent pas.');
   return finish(rules('ÉLEVÉ','Type exécutable détecté. CSN ne l’exécute pas.',sig,ind),file);
 }
 if(sig==='OLE/Office ancien'){
   const raw=bytesToLatin1(head),ind=['Format OLE ancien : l’inspection interne est limitée.'];let level='MODÉRÉ';
   if(/VBA|_VBA_PROJECT|AutoOpen|Workbook_Open|Document_Open/i.test(raw)){level='ÉLEVÉ';ind.push('Indices de macro/VBA repérés dans la portion analysée.');}
   if(mismatch)ind.push('Extension et signature ne correspondent pas.');
   return finish(rules(level,'Document Office ancien ou conteneur OLE reconnu.', 'Office ancien / OLE',ind),file);
 }
 if(sig==='PDF'||ext==='pdf'){
   const tailLen=Math.min(file.size,131072),tail=new Uint8Array(await file.slice(Math.max(0,file.size-tailLen)).arrayBuffer());
   const raw=bytesToLatin1(head)+'\n'+bytesToLatin1(tail);const ind=[];let level='NORMAL';
   if(!bytesToLatin1(head.subarray(0,Math.min(head.length,1024))).includes('%PDF-')){level=maxLevel(level,'MODÉRÉ');ind.push('Signature PDF atypique ou absente au début du fichier.');}
   if(!bytesToLatin1(tail).includes('%%EOF')){level=maxLevel(level,'MODÉRÉ');ind.push('Marque de fin PDF %%EOF non repérée dans la fin du fichier.');}
   const c2pa=/\/AFRelationship\s*\/C2PA_Manifest\b|application(?:#2F|\/)c2pa|\(Content Credentials\)/i.test(raw);
   const pdfNames=pdfStructuralNames(bytesToLatin1(head));
   ind.push('Inspection heuristique : flux compressés non analysés ; absence d’indice ne garantit pas l’innocuité.');
   if(file.size>MAX_SCAN){level=maxLevel(level,'MODÉRÉ');ind.push('PDF trop volumineux : structure inspectée partiellement.');}
   const js=pdfNames.has('JavaScript')||pdfNames.has('JS'),launch=pdfNames.has('Launch'),auto=pdfNames.has('OpenAction')||pdfNames.has('AA'),embedded=pdfNames.has('EmbeddedFile')||pdfNames.has('Filespec'),xfa=pdfNames.has('XFA'),uri=pdfNames.has('URI');
   if(js){level='ÉLEVÉ';ind.push('JavaScript PDF déclaré.');}
   if(launch){level='ÉLEVÉ';ind.push('Action /Launch détectée.');}
   if(auto&&!js&&!launch){level=maxLevel(level,'MODÉRÉ');ind.push('Action automatique PDF déclarée.');}
   if(embedded&&!c2pa){level=maxLevel(level,'MODÉRÉ');ind.push('Fichier ou objet embarqué déclaré dans le PDF.');}
   if(c2pa)ind.push('Content Credentials (C2PA) détectées : métadonnées de provenance, non considérées comme une menace à elles seules.');
   if(xfa){level=maxLevel(level,'MODÉRÉ');ind.push('Formulaire XFA détecté.');}
   if(uri)ind.push('Lien(s) URI déclaré(s) dans le document.');
   if(mismatch){level=maxLevel(level,'MODÉRÉ');ind.push('Extension et signature ne correspondent pas.');}
   return finish(rules(level,level==='NORMAL'?'Structure PDF cohérente dans le périmètre inspecté.':'Le PDF contient un ou plusieurs éléments demandant de la prudence.','PDF',ind),file);
 }
 if(sig==='ZIP'){
   const z=await zipCentral(file),entries=z.entries,low=entries.map(e=>e.name.toLowerCase()),ind=[];let level='NORMAL';
   if(z.warning){level=maxLevel(level,'MODÉRÉ');ind.push(z.warning)}
   if(entries.some(e=>e.flags&1)){level=maxLevel(level,'MODÉRÉ');ind.push('Une ou plusieurs entrées ZIP sont chiffrées : leur contenu n’est pas inspectable.')}
   const trav=entries.filter(e=>e.name.includes('../')||e.name.includes('..\\')).slice(0,5);if(trav.length){level='ÉLEVÉ';ind.push('Chemin ZIP potentiellement dangereux : '+trav.map(e=>e.name).join(', '));}
   const dangerRe=/\.(exe|dll|scr|msi|com|bat|cmd|ps1|vbs|vbe|js|jse|wsf|wsh|hta|lnk|jar|sh)$/i;const d=entries.filter(e=>dangerRe.test(e.name)).slice(0,8);if(d.length){level='ÉLEVÉ';ind.push('Contenu exécutable/script : '+d.map(e=>e.name).join(', '));}
   if(low.some(n=>n.includes('vbaproject.bin')||n.includes('_vba_project'))){level='ÉLEVÉ';ind.push('Projet VBA / macro Office détecté.');}
   if(low.some(n=>n.includes('/activex/')||n.startsWith('activex/'))){level='ÉLEVÉ';ind.push('Composant ActiveX détecté.');}
   if(low.some(n=>n.includes('/embeddings/')||n.includes('oleobject'))){level=maxLevel(level,'MODÉRÉ');ind.push('Objet incorporé Office détecté.');}
   if(low.some(n=>n.includes('externallinks'))){level=maxLevel(level,'MODÉRÉ');ind.push('Lien externe Office détecté.');}
   const totalComp=entries.reduce((a,e)=>a+(e.comp||0),0),totalUn=entries.reduce((a,e)=>a+(e.uncomp||0),0),ratio=totalComp?totalUn/totalComp:0;
   if(totalUn>1024*1024*1024||ratio>1000){level='ÉLEVÉ';ind.push('Archive à expansion anormalement élevée (risque de saturation lors de l’extraction).');}
   else if(totalUn>200*1024*1024||ratio>200){level=maxLevel(level,'MODÉRÉ');ind.push('Archive fortement compressée ou volumineuse après extraction.');}
   let kind='Archive ZIP';
   const isAPK=ext==='apk'||low.includes('androidmanifest.xml')||low.some(n=>n.endsWith('classes.dex'));
   if(isAPK){kind='Application Android (APK)';level='ÉLEVÉ';ind.push('Paquet installable Android : son installation exécute du code et demande une provenance vérifiée.');}
   else if(ext==='jar'){kind='Archive Java (JAR)';level='ÉLEVÉ';ind.push('Archive Java pouvant contenir du code exécutable.');}
   else if(['docx','docm'].includes(ext)||low.includes('word/document.xml'))kind='Document Word OOXML';
   else if(['xlsx','xlsm'].includes(ext)||low.includes('xl/workbook.xml'))kind='Classeur Excel OOXML';
   else if(['pptx','pptm'].includes(ext)||low.includes('ppt/presentation.xml'))kind='Présentation PowerPoint OOXML';
   else if(['odt','ods','odp'].includes(ext)||low.some(n=>n==='meta-inf/manifest.xml'))kind='Document OpenDocument';
   if(['docm','xlsm','pptm'].includes(ext)&&!ind.some(x=>x.includes('VBA'))){level='ÉLEVÉ';ind.push('Extension Office autorisant les macros.');}
   if(mismatch){level=maxLevel(level,'MODÉRÉ');ind.push('Extension et signature ne correspondent pas.');}
   const count=(z.totalDeclared != null ? z.totalDeclared : entries.length);const obs=entries.length?`${kind} reconnu ; ${count} entrée(s) déclarée(s), ${entries.length} inspectée(s) dans le répertoire central.`:`${kind} reconnu ; contenu interne non listé complètement.`;
   return finish(rules(level,obs,kind,ind),file);
 }
 const textLike=(mime.startsWith('text/')||['txt','csv','log','md','json','xml','html','htm','svg','css','yaml','yml','ini','conf','sql'].includes(ext));
 if(textLike){
   const txt=await file.slice(0,Math.min(file.size,MAX_TEXT)).text(),s=txt.toLowerCase(),ind=[];let level='NORMAL';let type='Texte / '+(ext||'générique');
   if(['html','htm','svg'].includes(ext)){
     const script=/<script\b/i.test(txt),events=/\son(?:load|error|click|mouseover|focus)\s*=/i.test(txt),evalish=/\beval\s*\(|\bnew\s+Function\s*\(|\batob\s*\(/i.test(txt),net=/\bfetch\s*\(|XMLHttpRequest|WebSocket\s*\(/i.test(txt);
     if(script||events){level=maxLevel(level,'MODÉRÉ');ind.push('Contenu actif HTML/SVG (script ou gestionnaire d’événement) détecté.');}
     if(evalish&&net){level='ÉLEVÉ';ind.push('Combinaison de code dynamique et de communication réseau détectée.');}
   }
   if(ext==='csv'){
     const bad=txt.split(/\r?\n/).slice(0,3000).filter(line=>/(^|[,;\t])\s*[=@]/.test(line));
     if(bad.length){level=maxLevel(level,'MODÉRÉ');ind.push('Formule potentiellement active dans le CSV.');}
   }
   if(['xml'].includes(ext)&&/<!DOCTYPE[\s\S]{0,1000}\bSYSTEM\b/i.test(txt)){level=maxLevel(level,'MODÉRÉ');ind.push('Déclaration XML externe (SYSTEM) détectée.');}
   if(file.size>MAX_TEXT){level=maxLevel(level,'MODÉRÉ');ind.push('Analyse partielle : seuls les 2 premiers Mo de texte ont été examinés.');}
   if(!txt.trim()){level=maxLevel(level,'MODÉRÉ');ind.push('Fichier texte vide.');}
   return finish(rules(level,level==='NORMAL'?'Contenu texte lisible ; aucun comportement actif inhabituel détecté dans la portion inspectée.':'Le contenu texte présente un élément actif ou atypique à vérifier.',type,ind),file);
 }
 if(['PNG','JPEG','GIF'].includes(sig)||['png','jpg','jpeg','gif','webp','bmp','heic','heif'].includes(ext)){
   const level=mismatch?'MODÉRÉ':'NORMAL',ind=mismatch?['Extension et signature d’image ne correspondent pas.']:[];
   return finish(rules(level,level==='NORMAL'?'Fichier image reconnu. Inspection de structure de base réussie.':'Image déclarée avec incohérence de signature.','Image',ind),file);
 }
 if(['MP3','MP4/ISO Media','RIFF'].includes(sig)||['mp3','wav','m4a','mp4','mov','avi','webm','ogg','flac'].includes(ext)){
   const level=mismatch?'MODÉRÉ':'NORMAL',ind=mismatch?['Extension et signature multimédia ne correspondent pas.']:[];
   return finish(rules(level,'Fichier multimédia reconnu. Inspection limitée à la signature et aux métadonnées de base.','Audio / Vidéo',ind),file);
 }
 if(['RAR','7Z'].includes(sig)||['rar','7z','gz','tar','tgz','bz2','xz'].includes(ext)){
   return finish(rules('MODÉRÉ','Archive reconnue, mais son contenu interne n’est pas décompressé par cette version autonome.','Archive compressée',['Vérification du contenu interne non disponible pour ce format.']),file);
 }
 const ind=[];if(mismatch)ind.push('Extension et signature ne correspondent pas.');
 return finish(rules('MODÉRÉ','Format non identifié ou non inspectable en profondeur. CSN a vérifié les informations de base sans exécuter le fichier.','Format non identifié',ind),file);
}

function resetUI(){
 $('resumeSimple').textContent='Choisissez un contenu, puis lancez son examen.';$('detailsAnalyse').open=false;
 $('fichierCSN').value='';$('inspection').textContent='Aucun fichier inspecté.';$('typeDetecte').textContent='—';$('niveau').textContent='—';$('niveau').className='muted';$('taille').textContent='—';$('hash').textContent='—';$('observation').textContent='Aucune observation.';$('indices').textContent='Aucun indice enregistré.';$('decision').textContent='Aucune décision.';$('protection').textContent='Aucune mesure.';$('etat').textContent='PRÊT — Fichier : analyse à la sélection ; message : analyse automatique après saisie ; lien : appuyez sur Examiner';$('etat').className='status ok';$('btnRapport').disabled=true;dernierRapport=null;
}
window.reportExportResult=function(ok,message){$('etat').textContent=message;$('etat').className='status '+(ok?'ok':'bad');alert(message);};
function downloadReport(){
 if(!dernierRapport)return;const r=dernierRapport;
 const txt=`CSN 1.6.3 — Vers un usage universel — RAPPORT D’INSPECTION\nDate : ${r.date}\nContenu examiné : ${r.nom}\nTaille : ${r.taille}\nExtension : ${r.extension}\nType déclaré : ${r.mime}\nType détecté : ${r.type}\nNiveau d’attention : ${r.niveau}\nSHA-256 : ${r.hash}\n\nPORTÉE DE L’EXAMEN\n${porteeRapport(r)}\n\nOBSERVATION\n${r.observation}\n\nÉLÉMENTS RELEVÉS ET LIMITES\n${r.indices.length?r.indices.map(x=>'- '+x).join('\n'):'Aucun indice technique inhabituel.'}\n\nQUE FAIRE MAINTENANT ?\n${r.decision}\n\nPROTECTION CONSEILLÉE\n${r.protection}\n\nNote : CSN 1.6.3 — Vers un usage universel est un outil local d’analyse de structure et d’indices ; il ne remplace pas un antivirus ou un bac à sable.\n`;
 const filename='CSN-Rapport-'+r.nom.replace(/[^a-z0-9._-]+/gi,'_')+'.txt';
 if(window.AndroidReport&&typeof window.AndroidReport.saveReport==='function'){
   try { window.AndroidReport.saveReport(txt,filename); } catch(e) { window.reportExportResult(false,'Export Android impossible : '+(e.message||e)); } return;
 }
 if(/; wv\)/i.test(navigator.userAgent)){window.reportExportResult(false,'La liaison Android du rapport est absente. Cette version doit être reconstruite puis installée.');return;}
 const blob=new Blob(['\uFEFF',txt],{type:'text/plain;charset=utf-8'}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=filename;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);
}
async function lancerInspectionSelectionnee(){if(occupe)return;const file=($('fichierCSN').files || [])[0];if(!file){$('inspection').textContent='Aucun fichier sélectionné.';return}try{occupe=true;$('fichierCSN').disabled=true;$('btnInspecter').disabled=true;await inspect(file)}catch(e){$('etat').textContent='ERREUR D’INSPECTION';$('etat').className='status bad';$('observation').textContent='Inspection interrompue : '+((e && e.message)||e);dernierRapport=null;$('btnRapport').disabled=true;addHist('Erreur — '+file.name)}finally{occupe=false;$('fichierCSN').disabled=false;$('btnInspecter').disabled=false}}
$('fichierCSN').addEventListener('change',()=>{if(($('fichierCSN').files && $('fichierCSN').files.length)) lancerInspectionSelectionnee();});
$('btnInspecter').addEventListener('click',lancerInspectionSelectionnee);
$('btnEffacer').addEventListener('click',()=>{try{localStorage.removeItem(CLE)}catch(erreurIgnoree){}renderHist()});
$('btnReset').addEventListener('click',()=>{if(!occupe){resetUI();$('messageCSN').value='';$('lienCSN').value='';derniereReparation=null;$('reparationZone').hidden=true;$('texteRepare').value=''}});$('btnRapport').addEventListener('click',downloadReport);renderHist();

const shorteners=new Set(['bit.ly','tinyurl.com','t.co','goo.gl','cutt.ly','is.gd','rb.gy','shorturl.at']);
function analyserLien(val){
 const ind=[];let level='NORMAL';let u;
 const raw=val.trim();
 try{u=new URL(raw)}catch(erreurIgnoree){return {level:'MODÉRÉ',indices:['Adresse non reconnue. Collez une adresse complète commençant par https:// ou http://.'],host:'non reconnu'}}
 if(!['https:','http:'].includes(u.protocol))return {level:'ÉLEVÉ',indices:['Protocole inhabituel : '+u.protocol+' ; ne pas exécuter cette adresse.'],host:u.hostname||'sans domaine'};
 if(u.protocol==='http:'){level='MODÉRÉ';ind.push('Adresse HTTP : connexion non chiffrée. HTTPS ne garantit toutefois pas la fiabilité du site.');}
 if(u.username||u.password){level='ÉLEVÉ';ind.push('Identifiants avant le domaine (@) : présentation potentiellement trompeuse.');}
 const host=u.hostname.toLowerCase();ind.push('Domaine réel de destination : '+host);
 if(host.includes('xn--')){level=maxLevel(level,'MODÉRÉ');ind.push('Domaine internationalisé : vérifiez attentivement son orthographe.');}
 if(/^(\d{1,3}\.){3}\d{1,3}$/.test(host)||host.startsWith('[')){level=maxLevel(level,'MODÉRÉ');ind.push('Destination désignée par une adresse IP.');}
 if(host==='localhost'||host.endsWith('.local')){level=maxLevel(level,'MODÉRÉ');ind.push('Adresse locale : destination à vérifier.');}
 if(shorteners.has(host)){level=maxLevel(level,'MODÉRÉ');ind.push('Lien raccourci : destination finale non connue sans résolution réseau.');}
 if(/\.(exe|msi|apk|scr|bat|cmd|ps1|js|vbs)(?:$|\/)/i.test(u.pathname)){level='ÉLEVÉ';ind.push('Chemin évoquant un programme ou script téléchargeable.');}
 if(/%[0-9a-f]{2}/i.test(raw)){ind.push('Caractères encodés présents : ils peuvent être légitimes.');}
 ind.push('Site non visité ; redirections, réputation et contenu distant non vérifiés.');
 return {level,indices:ind,host};
}
function analyserMessage(txt){
 const ind=[];let level='NORMAL';const t=txt.normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
 const urgent=/urgent|immediat|derniere chance|dans les \d+ heures|compte.{0,25}(suspend|bloqu)|sous \d+ heures/.test(t);
 const secret=/(envoy|communiqu|transmett|partag|saisi|confirm|donn|fourniss|fournir|indiqu|dicte|repet|lis\b|lisez|demande).{0,80}(mot de passe|code.{0,15}(secret|confidentiel|pin|sms|verification|securite|otp)|numero.{0,15}carte|coordonnees bancaires)/s.test(t);
 const money=/virement|wave|orange money|paiement|payer|frais|transfert|bitcoin|crypto/.test(t);
 const prize=/gagne|loterie|heritage|gain garanti|rendement garanti/.test(t);
 if(urgent){level='MODÉRÉ';ind.push('Pression ou urgence : prenez le temps de vérifier.');}
 if(secret){level='ÉLEVÉ';ind.push('Demande apparente de données sensibles ou de code de vérification.');}
 if(money){ind.push('Référence à un paiement : confirmez le bénéficiaire par un canal connu.');if(urgent||prize)level=maxLevel(level,'MODÉRÉ');}
 if(prize){level=maxLevel(level,'MODÉRÉ');ind.push('Promesse de gain : vérifiez l’origine et les conditions.');}
 const urls=txt.match(/https?:\/\/[^\s<>"']+/gi)||[];
 for(const url of urls.slice(0,20)){const r=analyserLien(url.replace(/[),.;!?]+$/,''));level=maxLevel(level,r.level);ind.push(...r.indices.map(x=>'Lien : '+x));}
 if(urls.length>20){level=maxLevel(level,'MODÉRÉ');ind.push('Seuls les 20 premiers liens complets ont été examinés.');}
 ind.push('Analyse de formulations et de liens HTTP(S) complets uniquement ; identité de l’expéditeur, liens masqués et pièces jointes non vérifiés.');
 return {level,indices:ind};
}
function afficherAnalyseTexte(kind,value,r){
 if(occupe){alert('Attendez la fin de l’inspection du fichier.');return}
 if(!value.trim()){alert('Collez '+(kind==='Lien'?'une adresse complète.':'un message.'));return}
 $('taille').textContent=fmtSize(new Blob([value]).size);$('hash').textContent='Non calculée pour cette analyse';
 $('inspection').textContent=kind+' examiné localement. Le texte complet n’est pas enregistré ; certains domaines et éléments relevés peuvent figurer dans le rapport.';
 const result=rules(r.level,r.level==='NORMAL'?'Aucun indice inhabituel repéré par les règles disponibles.':'Un ou plusieurs indices demandent une vérification.',kind,r.indices);
 finish(result,{name:kind+' — analyse locale',size:new Blob([value]).size,type:'text/plain'});
}
for(const kind of ['Fichier','Message','Lien','Appel','IA'])$('tab'+kind).addEventListener('click',()=>{if(occupe)return;invaliderResultat();for(const k of ['Fichier','Message','Lien','Appel','IA']){$('panel'+k).hidden=k!==kind;$('tab'+k).setAttribute('aria-selected',String(k===kind))}});
$('btnMessage').addEventListener('click',()=>{const t=$('messageCSN').value;afficherAnalyseTexte('Message',t,analyserMessage(t))});
$('btnLien').addEventListener('click',()=>{const t=$('lienCSN').value;afficherAnalyseTexte('Lien',t,analyserLien(t))});


function analyserContexte(texte,mode){
 const r=analyserMessage(texte);
 const t=texte.normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
 const signaler=(motif,description,niveau='MODÉRÉ')=>{if(motif.test(t)){r.level=maxLevel(r.level,niveau);r.indices.push(description)}};
 if(mode==='Appel'){
 signaler(/anydesk|teamviewer|prise de controle|acces a distance|partag.{0,25}ecran/,'Demande possible d’accès à distance : ne donnez pas le contrôle de votre appareil à un interlocuteur non vérifié.','ÉLEVÉ');
 signaler(/secret|ne.{0,15}dites.{0,15}personne|restez en ligne/,'Consigne de secret ou de maintien en ligne : raccrochez et vérifiez par un numéro connu.');
 r.indices.push('La voix et le numéro affiché ne sont pas authentifiés par cet examen.');
 }else{
 signaler(/ignore.{0,30}instruction|desactive.{0,30}(securite|protection)|contourne.{0,30}(securite|protection)/,'Instruction visant à ignorer des consignes ou désactiver des protections : vérifiez son contexte.');
 signaler(/cle api|api key|token.{0,20}(secret|acces)|mot de passe|code otp/,'Données d’accès évoquées : ne transmettez pas de secret à une IA.');
 signaler(/execute.{0,30}(commande|script)|powershell|curl.{0,80}\||rm -rf/,'Commande ou exécution de code évoquée : faites examiner le code avant de l’utiliser.');
 r.indices.push('CSN ne confirme pas la vérité d’une réponse ni l’existence de ses sources.');
 }
 return r;
}
for(const [mode,champ] of [['Appel','appelCSN'],['IA','iaCSN']]){
 $(champ).addEventListener('input',invaliderResultat);
 $('btn'+mode).addEventListener('click',()=>{const t=$(champ).value;afficherAnalyseTexte(mode,t,analyserContexte(t,mode))});
}
$('btnReset').addEventListener('click',()=>{if(!occupe){$('appelCSN').value='';$('iaCSN').value=''}});

function reparerTexte(original){
 let texte=original, corrections=0;
 const caracteres='àâäéèêëîïôöùûüçÀÂÄÉÈÊËÎÏÔÖÙÛÜÇœŒ’“”–—€';
 const decoder=new TextDecoder('windows-1252');
 for(const c of caracteres){
   const mauvais=decoder.decode(new TextEncoder().encode(c));
   const n=texte.split(mauvais).length-1;
   if(n){texte=texte.split(mauvais).join(c);corrections+=n;}
 }
 let retraits=0;const liens=[];
 texte=texte.replace(/https?:\/\/[^\s<>"']+/gi,raw=>{
   const url=raw.replace(/[),.;!?]+$/,'');
   const suffixe=raw.slice(url.length);
   const r=analyserLien(url);
   if(r.level==='NORMAL')return raw;
   retraits++;liens.push(r.host);
   return '[LIEN RETIRÉ PAR CSN]'+suffixe;
 });
 return {texte,corrections,retraits,liens};
}
let derniereReparation=null;
function telechargerTexteRepare(texte,nom){
 if(window.AndroidReport&&typeof window.AndroidReport.saveReport==='function'){
   try{window.AndroidReport.saveReport('\uFEFF'+texte,nom)}catch(e){alert('Téléchargement impossible : '+e.message)}return;
 }
 const url=URL.createObjectURL(new Blob(['\uFEFF',texte],{type:'text/plain;charset=utf-8'}));
 const a=document.createElement('a');a.href=url;a.download=nom;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),3000);
}
$('btnReparer').addEventListener('click',()=>{
 if(occupe){alert('Attendez la fin de l’inspection.');return}
 const original=$('messageCSN').value;
 if(!original.trim()){alert('Collez un message à réparer.');return}
 const r=reparerTexte(original);
 const avant=analyserMessage(original);
 const analyse=analyserMessage(r.texte);
 const bilan='CSN — RAPPORT DE RÉPARATION\nDate : '+new Date().toLocaleString('fr-FR')+'\nAccents corrigés : '+r.corrections+'\nLiens retirés : '+r.retraits+'\nNiveau avant modification : '+avant.level+'\nNiveau de la copie après modification : '+analyse.level+'\n\n'+analyse.indices.join('\n')+'\n\nQUE FAIRE MAINTENANT ?\n'+rules(analyse.level,'','Message').decision+'\n'+rules(analyse.level,'','Message').protection+'\n\nUn niveau plus bas après modification ne prouve pas la fiabilité du message original.\nOriginal conservé. Aucun lien ouvert. Les liens non repérés, les demandes trompeuses et les pièces jointes peuvent rester dangereux. Aucun fichier infecté n’a été désinfecté.';
 derniereReparation={texte:r.texte,bilan};
 $('texteRepare').value=r.texte;$('bilanReparation').textContent=bilan;$('reparationZone').hidden=false;
});
$('btnReparationResultat').addEventListener('click',async()=>{
 if(!$('panelAppel').hidden||!$('panelIA').hidden){alert('La copie réparée concerne le mode Message et les fichiers TXT.');return;}
 if(occupe){alert('Attendez la fin de l’inspection.');return;}
 const fichier=$('fichierCSN').files[0];
 const modeFichier=!$('panelFichier').hidden;
 if(modeFichier&&fichier){
   if(!/\.txt$/i.test(fichier.name)){alert('La réparation automatique concerne les messages et fichiers TXT. Ce format ne peut pas être réparé par CSN.');return;}
   if(fichier.size>50000){alert('Réparation limitée aux fichiers TXT de 50 000 octets maximum.');return;}
   try{
     const bytes=new Uint8Array(await fichier.arrayBuffer());
     const texte=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
     if(texte.includes('\u0000'))throw new Error('Contenu binaire');
     $('messageCSN').value=texte;
   }catch(e){alert('Ce fichier ne peut pas être réparé : un texte UTF-8 lisible est nécessaire.');return;}
 }
 $('tabMessage').click();
 if($('messageCSN').value.trim())$('btnReparer').click();
 else $('messageCSN').focus();
 $('btnReparer').scrollIntoView({block:'center'});
});
let minuterieMessage=null;
$('messageCSN').addEventListener('input',()=>{
 clearTimeout(minuterieMessage);invaliderResultat();derniereReparation=null;$('reparationZone').hidden=true;$('texteRepare').value='';
 if($('messageCSN').value.trim())minuterieMessage=setTimeout(()=>{
  const t=$('messageCSN').value;
  if(!occupe&&!$('panelMessage').hidden&&t.trim())afficherAnalyseTexte('Message',t,analyserMessage(t));
 },800);
});
$('btnReset').addEventListener('click',()=>clearTimeout(minuterieMessage));
for(const k of ['Fichier','Message','Lien','Appel','IA'])$('tab'+k).addEventListener('click',()=>clearTimeout(minuterieMessage));
$('lienCSN').addEventListener('input',invaliderResultat);
$('btnReset').addEventListener('click',()=>{if(occupe)return;derniereReparation=null;$('reparationZone').hidden=true;$('texteRepare').value=''});
$('btnCopieReparee').addEventListener('click',()=>{if(derniereReparation)telechargerTexteRepare(derniereReparation.texte,'CSN-Copie-reparee.txt')});
$('btnBilanReparation').addEventListener('click',()=>{if(derniereReparation)telechargerTexteRepare(derniereReparation.bilan,'CSN-Rapport-reparation.txt')});

for(const [mode,champ] of [['Message','messageCSN'],['Appel','appelCSN'],['IA','iaCSN'],['Lien','lienCSN']]){
 $('effacer'+mode).addEventListener('click',()=>{
  if(occupe)return;
  clearTimeout(minuterieMessage);$(champ).value='';invaliderResultat();
  derniereReparation=null;$('reparationZone').hidden=true;$('texteRepare').value='';$('bilanReparation').textContent='';
  $('inspection').textContent='Champ vidé. Collez ou saisissez un nouveau contenu.';$(champ).focus();
 });
}
 document.getElementById('etat').textContent='PRÊT — Commandes initialisées';
} catch (erreurDemarrage) { document.getElementById('etat').textContent='DÉMARRAGE BLOQUÉ : '+erreurDemarrage.message; }
})();
