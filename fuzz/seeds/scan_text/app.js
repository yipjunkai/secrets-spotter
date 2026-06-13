/* Acme dashboard client bundle (synthetic, trimmed for benchmarking). */
(function () {
  "use strict";

  var config = JSON.parse(
    document.getElementById("bootstrap-config").textContent
  );

  var endpoints = {
    projects: config.apiBase + "/projects",
    usage: config.apiBase + "/usage",
    billing: config.apiBase + "/billing/summary",
    events: config.apiBase + "/events?limit=50",
  };

  function request(path, options) {
    options = options || {};
    var headers = {
      "Accept": "application/json",
      "Content-Type": "application/json",
      "X-Acme-Client": "dashboard-web/2026.6.0",
      "X-Acme-Locale": config.locale,
    };
    return fetch(path, {
      method: options.method || "GET",
      headers: headers,
      credentials: "same-origin",
      body: options.body ? JSON.stringify(options.body) : undefined,
    }).then(function (res) {
      if (!res.ok) {
        throw new Error("request failed: " + res.status + " " + path);
      }
      return res.json();
    });
  }

  function formatNumber(n) {
    if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
    if (n >= 1e3) return (n / 1e3).toFixed(1) + "k";
    return String(n);
  }

  function renderCards(summary) {
    Object.keys(summary).forEach(function (key) {
      var el = document.querySelector('[data-metric="' + key + '"] .big-number');
      if (el) el.textContent = formatNumber(summary[key]);
    });
  }

  function renderProjects(projects) {
    var tbody = document.querySelector(".data-table tbody");
    if (!tbody) return;
    var rows = projects
      .map(function (p) {
        var status = p.healthy ? "healthy" : "degraded";
        return (
          '<tr data-project-id="' + p.id + '">' +
          "<td>" + p.name + "</td>" +
          "<td>" + p.environment + "</td>" +
          "<td>" + p.lastDeployAt + "</td>" +
          '<td><span class="badge">' + status + "</span></td>" +
          "</tr>"
        );
      })
      .join("");
    tbody.innerHTML = rows;
  }

  function debounce(fn, wait) {
    var t = null;
    return function () {
      var args = arguments,
        ctx = this;
      clearTimeout(t);
      t = setTimeout(function () {
        fn.apply(ctx, args);
      }, wait);
    };
  }

  function wireSearch() {
    var input = document.getElementById("q");
    if (!input) return;
    var handler = debounce(function () {
      var term = input.value.trim();
      if (term.length < 2) return;
      request(endpoints.projects + "?q=" + encodeURIComponent(term))
        .then(renderProjects)
        .catch(function (err) {
          console.warn("search error", err.message);
        });
    }, 200);
    input.addEventListener("input", handler);
  }

  function init() {
    Promise.all([
      request(endpoints.usage),
      request(endpoints.projects),
    ])
      .then(function (results) {
        renderCards(results[0]);
        renderProjects(results[1]);
      })
      .catch(function (err) {
        console.error("dashboard init failed", err.message);
      });
    wireSearch();
  }

  if (document.readyState !== "loading") {
    init();
  } else {
    document.addEventListener("DOMContentLoaded", init);
  }
})();
