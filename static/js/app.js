const sidebar=document.getElementById("sidebar");
const menuButton=document.getElementById("menuButton");
const personalPanel=document.getElementById("personalPanel");
const personalButton=document.getElementById("personalButton");
const closePersonal=document.getElementById("closePersonal");

if(menuButton&&sidebar){menuButton.addEventListener("click",()=>sidebar.classList.toggle("open"));}
if(personalButton&&personalPanel){personalButton.addEventListener("click",()=>personalPanel.classList.add("open"));}
if(closePersonal&&personalPanel){closePersonal.addEventListener("click",()=>personalPanel.classList.remove("open"));}
