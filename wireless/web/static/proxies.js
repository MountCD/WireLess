(() => {
  const { api } = window.WireLess;
  const tableBody = document.getElementById("proxies-body");
  if (!tableBody) return;

  const form = document.getElementById("add-form");
  const urlInput = document.getElementById("url");
  const nameInput = document.getElementById("name");
  const formError = document.getElementById("form-error");
  const previewBox = document.getElementById("preview-box");
  const empty = document.getElementById("empty");
  const listError = document.getElementById("list-error");

  function showError(element, message) {
    element.textContent = message;
    element.hidden = false;
  }

  function hideError(element) {
    element.hidden = true;
  }

  function renderRow(config, activeName) {
    const row = document.createElement("tr");
    const isActive = config.name === activeName;
    if (isActive) row.classList.add("is-active");

    const name = document.createElement("td");
    name.textContent = config.name || "—";
    if (isActive) {
      const badge = document.createElement("span");
      badge.className = "badge";
      badge.dataset.state = "ok";
      badge.textContent = "active";
      name.append(" ", badge);
    }

    const type = document.createElement("td");
    type.textContent = config._type || config.type || "?";

    const server = document.createElement("td");
    server.className = "mono";
    server.textContent = `${config.server}:${config.port}`;

    const actions = document.createElement("td");
    actions.className = "row-actions";

    if (!isActive) {
      const activate = document.createElement("button");
      activate.type = "button";
      activate.className = "ghost small";
      activate.dataset.action = "activate";
      activate.dataset.name = config.name;
      activate.textContent = "Активировать";
      actions.append(activate);
    }

    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "ghost small danger";
    remove.dataset.action = "delete";
    remove.dataset.name = config.name;
    remove.textContent = "Удалить";
    actions.append(remove);

    row.append(name, type, server, actions);
    return row;
  }

  async function load() {
    try {
      const data = await api("/api/proxies");
      tableBody.replaceChildren();
      data.configs.forEach((config) => {
        tableBody.append(renderRow(config, data.active));
      });
      empty.hidden = data.configs.length > 0;
      hideError(listError);
    } catch (error) {
      if (error.status === 401) {
        window.location.assign("/login");
        return;
      }
      showError(listError, error.message);
    }
  }

  async function preview() {
    hideError(formError);
    try {
      const parsed = await api("/api/proxies/parse", {
        method: "POST",
        body: { url: urlInput.value },
      });
      const label = parsed.name || "без имени";
      previewBox.textContent = `${parsed._type} · ${parsed.server}:${parsed.port} · ${label}`;
      previewBox.hidden = false;
    } catch (error) {
      previewBox.hidden = true;
      showError(formError, error.message);
    }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    hideError(formError);
    try {
      await api("/api/proxies", {
        method: "POST",
        body: { url: urlInput.value, name: nameInput.value },
      });
      form.reset();
      previewBox.hidden = true;
      await load();
    } catch (error) {
      showError(formError, error.message);
    }
  });

  document.getElementById("preview").addEventListener("click", preview);

  tableBody.addEventListener("click", async (event) => {
    const button = event.target.closest("button[data-action]");
    if (!button) return;

    const name = button.dataset.name;
    hideError(listError);
    try {
      if (button.dataset.action === "activate") {
        await api("/api/proxies/activate", { method: "POST", body: { name } });
      } else if (button.dataset.action === "delete") {
        if (!window.confirm(`Удалить конфиг «${name}»?`)) return;
        await api(`/api/proxies?name=${encodeURIComponent(name)}`, { method: "DELETE" });
      }
      await load();
    } catch (error) {
      showError(listError, error.message);
    }
  });

  load();
})();
