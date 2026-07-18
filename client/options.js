const tokenInput = document.getElementById("token");
const saveBtn = document.getElementById("save");
const status = document.getElementById("status");

browser.storage.local.get("token").then((data) => {
	if (data.token) {
		tokenInput.value = data.token;
	}
});

saveBtn.addEventListener("click", () => {
	browser.storage.local.set({ token: tokenInput.value }).then(() => {
		status.textContent = "Saved.";
		setTimeout(() => { status.textContent = ""; }, 2000);
	});
});
