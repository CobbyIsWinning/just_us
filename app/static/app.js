document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-password-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
      const input = button.parentElement.querySelector("[data-password-input]");
      const show = input.type === "password";
      input.type = show ? "text" : "password";
      button.textContent = show ? "Hide" : "Show";
      button.setAttribute("aria-pressed", String(show));
      button.setAttribute("aria-label", `${show ? "Hide" : "Show"} password`);
    });
  });
  const confirmation = document.querySelector("#confirm-password");
  if (confirmation) {
    const password = document.querySelector("#password");
    const validate = () =>
      confirmation.setCustomValidity(
        confirmation.value !== password.value
          ? "Your passwords don’t match."
          : "",
      );
    confirmation.addEventListener("input", validate);
    password.addEventListener("input", validate);
  }
  document.querySelectorAll("form[data-submit-guard]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      const message = form.querySelector('textarea[name="content"]');
      if (message && !message.value.trim()) {
        event.preventDefault();
        message.setCustomValidity("Write a message before sending.");
        message.reportValidity();
        return;
      }
      if (!form.checkValidity()) return;
      if (form.dataset.submitting === "true") {
        event.preventDefault();
        return;
      }
      form.dataset.submitting = "true";
      form.querySelectorAll("[data-submit-button]").forEach((button) => {
        button.disabled = true;
        button.setAttribute("aria-busy", "true");
        const label = button.querySelector("[data-submit-label]") || button;
        button.dataset.originalLabel = label.textContent;
        if (button.dataset.loadingText)
          label.textContent = button.dataset.loadingText;
      });
    });
  });
  document
    .querySelectorAll("textarea[data-submit-on-enter]")
    .forEach((textarea) => {
      textarea.addEventListener("input", () => {
        textarea.setCustomValidity("");
        textarea.style.height = "auto";
        textarea.style.height = `${Math.min(textarea.scrollHeight, 140)}px`;
      });
      textarea.addEventListener("keydown", (event) => {
        if (event.key === "Enter" && !event.shiftKey && !event.isComposing) {
          event.preventDefault();
          if (textarea.form.dataset.submitting !== "true")
            textarea.form.requestSubmit();
        }
      });
    });
  const timeline = document.querySelector("[data-timeline]");
  if (timeline && timeline.querySelector(".message"))
    timeline.scrollTop = timeline.scrollHeight;
  const search = document.querySelector("[data-log-search]");
  if (search) {
    let level = "all";
    const rows = [...document.querySelectorAll("[data-log-row]")];
    const filter = () => {
      let visible = 0;
      rows.forEach((row) => {
        row.hidden =
          (level !== "all" && row.dataset.level !== level) ||
          !row.textContent.toLowerCase().includes(search.value.toLowerCase());
        if (!row.hidden) visible++;
      });
      document.querySelector("[data-log-count]").textContent =
        `${visible} shown`;
      document.querySelector("[data-log-empty]").hidden =
        visible > 0 || rows.length === 0;
    };
    search.addEventListener("input", filter);
    document.querySelectorAll("[data-log-filter]").forEach((button) =>
      button.addEventListener("click", () => {
        level = button.dataset.logFilter;
        document
          .querySelectorAll("[data-log-filter]")
          .forEach((item) =>
            item.setAttribute("aria-pressed", String(item === button)),
          );
        filter();
      }),
    );
    filter();
  }
});
window.addEventListener("pageshow", () => {
  document.querySelectorAll("form[data-submitting]").forEach((form) => {
    delete form.dataset.submitting;
    form.querySelectorAll("[data-submit-button]").forEach((button) => {
      button.disabled = false;
      button.removeAttribute("aria-busy");
      if (button.dataset.originalLabel)
        (button.querySelector("[data-submit-label]") || button).textContent =
          button.dataset.originalLabel;
    });
  });
});
