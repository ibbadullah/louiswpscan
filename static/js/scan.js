/*
 * Louis WP Scan - home page scan flow.
 *
 * Submits the URL to the /scan/ endpoint with fetch(), plays a scanning
 * animation while the server works, then redirects to the result page.
 */
(function () {
    "use strict";

    var form = document.getElementById("lwps-scan-form");
    if (!form) { return; }

    var input = document.getElementById("lwps-url");
    var button = document.getElementById("lwps-scan-btn");
    var errorBox = document.getElementById("lwps-scan-error");
    var overlay = document.getElementById("lwps-scan-overlay");
    var statusEl = document.getElementById("lwps-scan-status");
    var targetEl = document.getElementById("lwps-scan-target");

    // Read localized animation strings rendered by the template.
    var i18n = { steps: [], genericError: "Something went wrong." };
    try {
        i18n = JSON.parse(document.getElementById("lwps-i18n").textContent);
    } catch (e) { /* keep defaults */ }

    var stepTimer = null;

    function getCookie(name) {
        var match = document.cookie.match("(^|;)\\s*" + name + "\\s*=\\s*([^;]+)");
        return match ? match.pop() : "";
    }

    function showError(msg) {
        errorBox.textContent = msg;
        errorBox.hidden = false;
    }

    function startAnimation(target) {
        errorBox.hidden = true;
        targetEl.textContent = target;
        overlay.hidden = false;
        overlay.classList.add("is-active");
        document.body.style.overflow = "hidden";

        var i = 0;
        if (i18n.steps.length) { statusEl.textContent = i18n.steps[0]; }
        stepTimer = setInterval(function () {
            i = (i + 1) % i18n.steps.length;
            statusEl.textContent = i18n.steps[i];
        }, 1100);
    }

    function stopAnimation() {
        clearInterval(stepTimer);
        overlay.classList.remove("is-active");
        overlay.hidden = true;
        document.body.style.overflow = "";
    }

    form.addEventListener("submit", function (e) {
        e.preventDefault();
        var url = (input.value || "").trim();
        if (!url || url.indexOf(".") === -1) {
            showError(i18n.genericError);
            input.focus();
            return;
        }

        button.disabled = true;
        startAnimation(url);

        fetch(form.dataset.action || "/scan/", {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "X-CSRFToken": getCookie("csrftoken")
            },
            body: JSON.stringify({ url: url })
        })
            .then(function (resp) { return resp.json().then(function (d) { return { ok: resp.ok, data: d }; }); })
            .then(function (res) {
                if (res.ok && res.data.ok && res.data.redirect) {
                    // Small pause so the animation feels complete, then go.
                    setTimeout(function () { window.location.href = res.data.redirect; }, 600);
                } else {
                    stopAnimation();
                    button.disabled = false;
                    showError((res.data && res.data.error) || i18n.genericError);
                }
            })
            .catch(function () {
                stopAnimation();
                button.disabled = false;
                showError(i18n.genericError);
            });
    });
})();
