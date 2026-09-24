// 计划表单保存后替换当前历史项，避免重复提交不断累积同一个页面。
document.addEventListener("submit", async (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement) || !form.hasAttribute("data-plan-navigation")) {
        return;
    }
    event.preventDefault();
    if (form.dataset.saving === "true") return;

    // FormData 默认不包含提交按钮，需保留确认删除按钮的确认值。
    const data = new FormData(form);
    const button = event.submitter;
    if (button && button.name) data.append(button.name, button.value);
    form.dataset.saving = "true";
    if (button) button.disabled = true;

    try {
        const response = await fetch(form.action || location.href, {
            method: "POST",
            body: data,
            credentials: "same-origin",
            headers: { "X-Plan-Navigation": "1" },
        });
        const destination = response.headers.get("X-Redirect-To");
        if (destination || response.redirected) {
            // 替换提交前的表单页面，浏览器后退仍返回之前访问的页面。
            location.replace(destination || response.url);
            return;
        }
        // 校验失败时显示服务端返回的输入和提示，不增加历史项，也不重复提交。
        const html = await response.text();
        const page = new DOMParser().parseFromString(html, "text/html");
        document.title = page.title;
        document.body.replaceChildren(...page.body.childNodes);
        const message = document.querySelector('[role="alert"], .login-error');
        if (message) {
            message.setAttribute("tabindex", "-1");
            message.focus();
        }
    } catch (error) {
        // 网络中断时不能自动重试写入，以免重复创建动作或计划。
        let message = form.querySelector('[data-submit-error]');
        if (!message) {
            message = document.createElement("p");
            message.dataset.submitError = "true";
            message.setAttribute("role", "alert");
            form.prepend(message);
        }
        message.textContent = "Connection interrupted. Reload to check whether your changes were saved before trying again.";
    } finally {
        delete form.dataset.saving;
        if (button) button.disabled = false;
    }
});
