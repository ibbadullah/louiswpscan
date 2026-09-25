/*
 * Louis WP Scan - cookie consent and Google Analytics loader.
 *
 * Google Analytics is NEVER loaded until the visitor clicks "Accept all".
 * The choice is stored in localStorage so we do not ask again on every page.
 * The footer "Cookie settings" link calls window.LWPS_openConsent() to re-open
 * the banner so a visitor can change their mind at any time (GDPR requirement).
 */
(function () {
    "use strict";

    var STORAGE_KEY = "lwps_consent_v1";
    var banner = document.getElementById("lwps-cookie-banner");

    function getConsent() {
        try { return localStorage.getItem(STORAGE_KEY); } catch (e) { return null; }
    }

    function setConsent(value) {
        try { localStorage.setItem(STORAGE_KEY, value); } catch (e) { /* ignore */ }
    }

    function showBanner() {
        if (banner) { banner.hidden = false; banner.classList.add("is-visible"); }
    }

    function hideBanner() {
        if (banner) { banner.classList.remove("is-visible"); banner.hidden = true; }
    }

    // Load Google Analytics 4 only when allowed.
    function loadAnalytics() {
        var gaId = window.LWPS_GA_ID;
        if (!gaId || window.__lwpsGaLoaded) { return; }
        window.__lwpsGaLoaded = true;

        var s = document.createElement("script");
        s.async = true;
        s.src = "https://www.googletagmanager.com/gtag/js?id=" + encodeURIComponent(gaId);
        document.head.appendChild(s);

        window.dataLayer = window.dataLayer || [];
        function gtag() { window.dataLayer.push(arguments); }
        window.gtag = gtag;
        gtag("js", new Date());
        // IP anonymisation on, keeps us friendly to EU privacy rules.
        gtag("config", gaId, { anonymize_ip: true });
    }

    function accept() { setConsent("accepted"); hideBanner(); loadAnalytics(); }
    function reject() { setConsent("rejected"); hideBanner(); }

    // Wire up the buttons.
    if (banner) {
        banner.querySelectorAll("[data-consent]").forEach(function (btn) {
            btn.addEventListener("click", function () {
                this.getAttribute("data-consent") === "accept" ? accept() : reject();
            });
        });
    }

    // Let the footer link reopen the banner.
    window.LWPS_openConsent = showBanner;

    // On page load: apply a stored choice, or show the banner the first time.
    var stored = getConsent();
    if (stored === "accepted") {
        loadAnalytics();
    } else if (stored !== "rejected") {
        showBanner();
    }
})();
