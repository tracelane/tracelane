#!/usr/bin/env node
/** Rebuild every brand asset from the founder's traced SVG (2026-10-12).
 * The SVG path is the sole geometry source; Playwright is already a web workspace
 * dependency and renders PNG/ICO pixels from that same path. */
import { createRequire } from "node:module";
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const require = createRequire(resolve(ROOT, "apps/web/package.json"));
const { chromium } = require("@playwright/test");
const master = readFileSync(resolve(ROOT, "apps/site/public/brand/tracelane-mark.svg"), "utf8");
const path = master.match(/<path[\s\S]*?\/>/)?.[0];
if (!path || !master.includes('viewBox="0 0 933 1034"') || !path.includes('M 461.500 32.626')) throw new Error("founder-traced mark master missing or changed");
const pathData = path.match(/d="([^"]+)"/)?.[1];
if (!pathData || /[^MCLZ\d.,\s-]/.test(pathData)) throw new Error("unsupported traced path commands");
const shape = (fill) => path.replace('fill="currentColor"', `fill="${fill}"`);
function placedShape(fill, x, y, width, height) {
  const scaleX = width / 933, scaleY = height / 1034;
  const placed = pathData.replace(/([MCL])([^MCLZ]*)/g, (_match, command, numbers) => {
    let axis = 0;
    const mapped = numbers.replace(/-?\d+(?:\.\d+)?/g, (value) => {
      const coordinate = axis++ % 2 === 0 ? x + Number(value) * scaleX : y + Number(value) * scaleY;
      return coordinate.toFixed(3);
    });
    return command + mapped;
  });
  return `<path d="${placed}" fill="${fill}"/>`;
}
const mark = (fill) => `<svg xmlns="http://www.w3.org/2000/svg" width="933" height="1034" viewBox="0 0 933 1034">${shape(fill)}</svg>`;
const lockup = (fill) => `<svg xmlns="http://www.w3.org/2000/svg" width="500" height="100" viewBox="0 0 500 100">${placedShape(fill,8,8,76,84)}<text x="110" y="68" font-family="Geist,Arial,sans-serif" font-size="62" font-weight="650" fill="${fill}">tracelane</text></svg>`;
const icon = (kind) => `<svg xmlns="http://www.w3.org/2000/svg" width="512" height="512" viewBox="0 0 512 512">${kind === "circle" ? '<circle cx="256" cy="256" r="252" fill="#050506"/>' : kind === "maskable" ? '<rect width="512" height="512" fill="#050506"/>' : '<rect x="4" y="4" width="504" height="504" rx="112" fill="#050506"/>'}${kind === "maskable" ? placedShape("#fff",135,115,242,282) : placedShape("#fff",105,76,302,360)}</svg>`;
const og = () => `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630"><defs><linearGradient id="bg" x2="1" y2="1"><stop stop-color="#fbfcff"/><stop offset="1" stop-color="#f8faff"/></linearGradient></defs><rect width="1200" height="630" fill="url(#bg)"/><circle cx="600" cy="298" r="184" fill="#050506"/>${placedShape("#fff",491,170,218,257)}<text x="600" y="545" text-anchor="middle" fill="#0d1330" font-family="Geist,Arial,sans-serif" font-size="58" font-weight="650" letter-spacing="-2">tracelane</text></svg>`;
const poster = (tour) => `<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="720" viewBox="0 0 1280 720"><defs><linearGradient id="bg" x2="1" y2="1"><stop stop-color="#fcfdff"/><stop offset="1" stop-color="#f8faff"/></linearGradient></defs><rect width="1280" height="720" fill="url(#bg)"/><rect x="88" y="215" width="270" height="270" rx="58" fill="#050506"/>${placedShape("#fff",145,253,156,190)}<text x="425" y="218" fill="#4338ca" font-family="Geist,Arial,sans-serif" font-size="20" font-weight="700" letter-spacing="3">GATEWAY · OBSERVABILITY · AUDIT</text><text x="425" y="318" fill="#0d1330" font-family="Geist,Arial,sans-serif" font-size="67" font-weight="700" letter-spacing="-3">${tour ? "The flight recorder" : "One gateway for"}</text><text x="425" y="394" fill="#0d1330" font-family="Geist,Arial,sans-serif" font-size="67" font-weight="700" letter-spacing="-3">${tour ? "for AI agents" : "model calls"}</text><text x="425" y="454" fill="#4b5272" font-family="Geist,Arial,sans-serif" font-size="25">Tamper-evident evidence you can verify offline.</text><text x="91" y="660" fill="#0d1330" font-family="Geist,Arial,sans-serif" font-size="28" font-weight="650">tracelane</text></svg>`;
const font = readFileSync(resolve(ROOT, "apps/site/public/fonts/geist-var-latin.woff2")).toString("base64");
const css = `<style>@font-face{font-family:Geist;src:url(data:font/woff2;base64,${font}) format('woff2');font-weight:100 900}html,body{margin:0;background:transparent}svg{display:block;width:100%;height:100%}</style>`;
function ico(frames) {
  const header = Buffer.alloc(6 + frames.length * 16); header.writeUInt16LE(1,2); header.writeUInt16LE(frames.length,4);
  let offset = header.length;
  frames.forEach(({size,png},i) => { const j=6+i*16; header[j]=size===256?0:size; header[j+1]=size===256?0:size; header.writeUInt16LE(1,j+4); header.writeUInt16LE(32,j+6); header.writeUInt32LE(png.length,j+8); header.writeUInt32LE(offset,j+12); offset+=png.length; });
  return Buffer.concat([header,...frames.map(f=>f.png)]);
}
const browser = await chromium.launch();
const output = process.argv.includes("--verify") ? mkdtempSync(resolve(tmpdir(),"tracelane-logo-")) : ROOT;
const files = [];
function write(rel,data) { const name=resolve(output,rel); mkdirSync(dirname(name),{recursive:true}); writeFileSync(name,data); files.push(rel); }
async function render(svg,width,height,scale=1,format="png") {
  const context=await browser.newContext({viewport:{width,height},deviceScaleFactor:scale});
  const page=await context.newPage(); await page.setContent(`<!doctype html>${css}${svg}`); await page.evaluate(()=>document.fonts.ready);
  const image=await page.screenshot({omitBackground:format==="png",type:format,quality:format==="jpeg"?90:undefined}); await context.close(); return image;
}
async function verifyPng(png) {
  const page=await browser.newPage();
  const result=await page.evaluate(async b64 => { const img=new Image(); img.src='data:image/png;base64,'+b64; await img.decode(); const canvas=document.createElement('canvas');canvas.width=img.width;canvas.height=img.height;const ctx=canvas.getContext('2d');ctx.drawImage(img,0,0);const data=ctx.getImageData(0,0,img.width,img.height).data;let opaque=0,white=0,dark=0;for(let i=0;i<data.length;i+=4){if(data[i+3]>30)opaque++;if(data[i+3]>30 && data[i]>210 && data[i+1]>210 && data[i+2]>210)white++;if(data[i+3]>30 && data[i]<80 && data[i+1]<80 && data[i+2]<80)dark++}return {opaque,white,dark,total:img.width*img.height}; },png.toString('base64'));
  await page.close(); return result.opaque > result.total*.02 && (result.opaque < result.total*.99 || (result.white>100 && result.dark>100)) && (result.white>100 || result.dark>100);
}
try {
  for(const [rel,svg] of [
    ["brand/svg/tracelane-mark-black.svg",mark("#0d1330")],["brand/svg/tracelane-mark-white.svg",mark("#fff")],
    ["brand/svg/tracelane-lockup-horizontal-black.svg",lockup("#0d1330")],["brand/svg/tracelane-lockup-horizontal-white.svg",lockup("#fff")],
    ["apps/docs/logo/light.svg",lockup("#0d1330")],["apps/docs/logo/dark.svg",lockup("#fff")],["apps/docs/favicon.svg",icon("square")],
    ["apps/site/public/favicon.svg",icon("square")],["apps/web/public/favicon.svg",icon("square")],
  ])write(rel,svg);
  for(const [rel,svg,w,h,scale] of [
    ["brand/png/tracelane-mark-black-1024.png",mark("#0d1330"),1024,1024,1],
    ["brand/png/tracelane-mark-white-1024.png",mark("#fff"),1024,1024,1],
    ["brand/png/tracelane-icon-1024.png",icon("circle"),1024,1024,1],
    ["brand/png/tracelane-lockup-horizontal-black.png",lockup("#0d1330"),500,100,8],
    ["brand/png/tracelane-lockup-horizontal-white.png",lockup("#fff"),500,100,8],
    ["apps/site/public/og-default.png",og(),1200,630,1],
  ])write(rel,await render(svg,w,h,scale));
  write("apps/site/public/hero-tour-poster.jpg",await render(poster(true),1280,720,1,"jpeg"));
  for(const rel of ["apps/site/public/hero-poster.jpg","apps/site/public/hero-demo-poster.jpg"])
    write(rel,await render(poster(false),1280,720,1,"jpeg"));
  const frames=[];for(const size of [16,32,48,256])frames.push({size,png:await render(icon("square"),size,size)});
  const fav=ico(frames);
  for(const app of ["apps/site","apps/web"]){
    write(`${app}/public/brand/tracelane-mark.svg`,master);
    write(`${app}/public/brand/favicon-16.png`,frames[0].png);
    write(`${app}/public/brand/favicon-32.png`,frames[1].png);
    write(`${app}/public/brand/apple-touch-icon.png`,await render(icon("square"),180,180));
    if(app==="apps/web")for(const size of [192,512])write(`${app}/public/brand/pwa-${size}.png`,await render(icon("square"),size,size));
    if(app==="apps/web")write(`${app}/public/brand/pwa-maskable-512.png`,await render(icon("maskable"),512,512));
    write(`${app}/public/favicon.ico`,fav);
  }
  for(const rel of files.filter(f=>f.endsWith('.png'))){ if(!await verifyPng(readFileSync(resolve(output,rel)))) throw new Error(`blank or solid icon: ${rel}`); }
  if(process.argv.includes("--selftest")){
    const blank=await render('<svg xmlns="http://www.w3.org/2000/svg" width="64" height="64"/>',64,64);
    if(await verifyPng(blank))throw new Error('blank-icon negative control passed');
    console.log('brand selftest: blank icon refused; traced mark rendered; output PNGs decoded');
  }
  console.log(`brand ${process.argv.includes('--verify')?'verify':'build'}: ${files.length} assets from founder-traced SVG; PNGs decoded and nonblank`);
} finally { await browser.close(); if(output!==ROOT)rmSync(output,{recursive:true,force:true}); }
