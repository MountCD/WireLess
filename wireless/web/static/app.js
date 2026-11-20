(() => {
  const meta = document.querySelector('meta[name="csrf-token"]');
  const csrf = meta ? meta.content : "";

  async function api(path, { method = "GET", body } = {}) {
    const response = await fetch(path, {
      method,
      headers: {
        "Content-Type": "application/json",
        "X-CSRF-Token": csrf,
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });

    let data = {};
    try {
      data = await response.json();
    } catch (_) {
      /* empty or non-JSON body */
    }

    if (!response.ok) {
      const error = new Error(data.detail || `HTTP ${response.status}`);
      error.status = response.status;
      throw error;
    }
    return data;
  }

  function setState(element, ok, text) {
    if (!element) return;
    element.textContent = text;
    element.dataset.state = ok ? "ok" : "bad";
  }

  window.WireLess = { api, setState };

  function setupLogin() {
    const form = document.getElementById("login-form");
    if (!form) return;

    const errorBox = document.getElementById("login-error");
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      errorBox.hidden = true;

      const password = document.getElementById("password").value;
      try {
        await api("/api/login", { method: "POST", body: { password } });
        window.location.assign("/");
      } catch (error) {
        errorBox.textContent = error.message;
        errorBox.hidden = false;
      }
    });
  }

  function setupLogout() {
    const button = document.getElementById("logout");
    if (!button) return;

    button.addEventListener("click", async () => {
      try {
        await api("/api/logout", { method: "POST" });
      } catch (_) {
        /* ignore: navigation below clears the page anyway */
      }
      window.location.assign("/login");
    });
  }

  function setupDashboard() {
    const active = document.getElementById("active");
    if (!active) return;

    const el = {
      active,
      serverIp: document.getElementById("server-ip"),
      configs: document.getElementById("configs"),
      running: document.getElementById("running"),
      wg: document.getElementById("wg"),
      sb: document.getElementById("sb"),
      routing: document.getElementById("routing"),
      binary: document.getElementById("sb-binary"),
      updated: document.getElementById("updated"),
      error: document.getElementById("status-error"),
    };
    const buttons = Array.from(document.querySelectorAll("[data-gateway]"));

    function showError(message) {
      el.error.textContent = message;
      el.error.hidden = false;
    }

    async function refresh() {
      try {
        const status = await api("/api/status");

        el.active.textContent = status.active || "не выбран";
        el.serverIp.textContent = status.server_ip || "—";
        el.configs.textContent = String(status.configs_count);
        setState(el.running, status.running, status.running ? "запущен" : "остановлен");

        const wg = status.wireguard || {};
        setState(el.wg, wg.running, wg.running ? "running" : "stopped");

        const sb = status.singbox || {};
        const pid = sb.running && sb.pid ? ` (pid ${sb.pid})` : "";
        setState(el.sb, sb.running, sb.running ? `running${pid}` : "stopped");
        el.binary.textContent = sb.binary || "—";

        setState(el.routing, status.routing, status.routing ? "active" : "inactive");

        el.updated.textContent = "обновлено " + new Date().toLocaleTimeString();
        el.error.hidden = true;
      } catch (error) {
        if (error.status === 401) {
          window.location.assign("/login");
          return;
        }
        showError(error.message);
      }
    }

    async function runGateway(action) {
      if (action === "restart" && !window.confirm("Перезапустить шлюз? Трафик клиентов прервётся.")) {
        return;
      }
      buttons.forEach((button) => { button.disabled = true; });
      el.error.hidden = true;
      try {
        await api(`/api/gateway/${action}`, { method: "POST", body: {} });
        await refresh();
      } catch (error) {
        showError(error.message);
      } finally {
        buttons.forEach((button) => { button.disabled = false; });
      }
    }

    buttons.forEach((button) => {
      button.addEventListener("click", () => runGateway(button.dataset.gateway));
    });

    refresh();
    window.setInterval(refresh, 3000);
  }

  setupLogin();
  setupLogout();
  setupDashboard();
})();
