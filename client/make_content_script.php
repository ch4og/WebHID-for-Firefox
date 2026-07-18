<?php
$polyfill = file_get_contents("WebHID-for-Firefox.js");
file_put_contents("content_script.js", <<<EVA
window.addEventListener("message", function(event) {
	if (event.data && event.data.type === "webhid-open-options") {
		browser.runtime.sendMessage({ type: "open-options" });
	}
});
browser.storage.local.get("token").then(function(data) {
	var token = (data && data.token) ? data.token : "";
	var script = document.createElement("script");
	script.innerHTML = "window._webhid_token=" + JSON.stringify(token) + ";" + `{$polyfill}`;
	document.documentElement.appendChild(script);
});
EVA
);
