// Generates a self-signed cert for LOCAL development so the browser treats
// the site as a secure context (required by the Geolocation API off localhost).
// Run: npm run gen-cert   → writes certs/key.pem and certs/cert.pem
// Your browser will warn once; accept it for local testing only.
// In production, DO NOT use this — terminate TLS at a real proxy / load balancer.
import selfsigned from "selfsigned";
import { mkdirSync, writeFileSync } from "node:fs";

const attrs = [{ name: "commonName", value: "localhost" }];
const pems = await selfsigned.generate(attrs, {
  days: 365,
  keySize: 2048,
  algorithm: "sha256",
  extensions: [{ name: "subjectAltName", altNames: [
    { type: 2, value: "localhost" },
    { type: 7, ip: "127.0.0.1" },
  ] }],
});

mkdirSync("certs", { recursive: true });
writeFileSync("certs/key.pem", pems.private);
writeFileSync("certs/cert.pem", pems.cert);
console.log("Wrote certs/key.pem and certs/cert.pem (valid 365 days, localhost only).");
