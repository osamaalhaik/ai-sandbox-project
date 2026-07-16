(() => {
    const approvalForms = [
        ...document.querySelectorAll(
            '.approval-actions form[action*="/approvals/"]',
        ),
    ];

    if (!approvalForms.length) {
        return;
    }

    const escapeHtml = value => String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

    const state = {
        decisionId: "",
        action: "",
        form: null,
    };

    const overlay = document.createElement("div");

    overlay.className = "approval-dialog-overlay";
    overlay.hidden = true;

    overlay.innerHTML = `
        <section class="approval-dialog" role="dialog" aria-modal="true">
            <div class="approval-dialog-head">
                <div>
                    <span>Human Approval Workflow</span>
                    <h2 id="approvalDialogTitle">Security Decision</h2>
                </div>

                <button
                    id="approvalDialogClose"
                    type="button"
                    aria-label="Close decision dialog"
                >
                    ×
                </button>
            </div>

            <form id="approvalDecisionForm">
                <div class="approval-dialog-command">
                    <span>Command request</span>
                    <code id="approvalDialogCommand">—</code>
                </div>

                <label>
                    <span>Administrator</span>
                    <input
                        id="approvalAdmin"
                        name="admin"
                        type="text"
                        value="demo_admin"
                        autocomplete="username"
                        required
                    >
                </label>

                <label>
                    <span>Decision reason</span>
                    <textarea
                        id="approvalReason"
                        name="reason"
                        rows="4"
                        minlength="8"
                        required
                    ></textarea>
                </label>

                <div id="approvalDialogError" class="approval-dialog-error" hidden></div>

                <div class="approval-dialog-actions">
                    <button
                        id="approvalCancel"
                        class="button secondary"
                        type="button"
                    >
                        Cancel
                    </button>

                    <button
                        id="approvalSubmit"
                        class="button primary"
                        type="submit"
                    >
                        Submit Decision
                    </button>
                </div>
            </form>
        </section>
    `;

    document.body.appendChild(overlay);

    const title = document.getElementById(
        "approvalDialogTitle",
    );

    const command = document.getElementById(
        "approvalDialogCommand",
    );

    const adminInput = document.getElementById(
        "approvalAdmin",
    );

    const reasonInput = document.getElementById(
        "approvalReason",
    );

    const errorBox = document.getElementById(
        "approvalDialogError",
    );

    const submitButton = document.getElementById(
        "approvalSubmit",
    );

    const decisionForm = document.getElementById(
        "approvalDecisionForm",
    );

    const closeButton = document.getElementById(
        "approvalDialogClose",
    );

    const cancelButton = document.getElementById(
        "approvalCancel",
    );

    const notify = (message, type = "success") => {
        let stack = document.querySelector(
            ".approval-toast-stack",
        );

        if (!stack) {
            stack = document.createElement("div");
            stack.className = "approval-toast-stack";
            document.body.appendChild(stack);
        }

        const toast = document.createElement("div");

        toast.className = (
            `approval-toast approval-toast-${type}`
        );

        toast.textContent = message;
        stack.appendChild(toast);

        window.setTimeout(() => {
            toast.classList.add("visible");
        }, 10);

        window.setTimeout(() => {
            toast.classList.remove("visible");

            window.setTimeout(() => {
                toast.remove();
            }, 220);
        }, 2600);
    };

    const closeDialog = () => {
        overlay.hidden = true;
        document.body.classList.remove(
            "approval-dialog-open",
        );

        errorBox.hidden = true;
        errorBox.textContent = "";

        state.decisionId = "";
        state.action = "";
        state.form = null;
    };

    const openDialog = form => {
        const actionUrl = new URL(
            form.action,
            window.location.href,
        );

        const match = actionUrl.pathname.match(
            /^\/approvals\/([^/]+)\/(approve|reject)$/,
        );

        if (!match) {
            return;
        }

        const card = form.closest(".approval-card");

        const commandText = (
            card?.querySelector(
                ".approval-command code",
            )?.textContent?.trim()
            || "Unknown command"
        );

        state.decisionId = decodeURIComponent(
            match[1],
        );

        state.action = match[2];
        state.form = form;

        const approving = (
            state.action === "approve"
        );

        title.textContent = (
            approving
                ? "Approve Command"
                : "Reject Command"
        );

        command.textContent = commandText;

        reasonInput.value = (
            approving
                ? "Approved after administrator review of risk, targets, and execution policy."
                : "Rejected after administrator review because the requested execution does not satisfy the active security policy."
        );

        submitButton.textContent = (
            approving
                ? "Approve Command"
                : "Reject Command"
        );

        submitButton.className = (
            approving
                ? "button success-button"
                : "button danger-button"
        );

        overlay.hidden = false;

        document.body.classList.add(
            "approval-dialog-open",
        );

        window.setTimeout(() => {
            adminInput.focus();
            adminInput.select();
        }, 20);
    };

    approvalForms.forEach(form => {
        form.addEventListener(
            "submit",
            event => {
                event.preventDefault();
                event.stopImmediatePropagation();
                openDialog(form);
            },
            true,
        );
    });

    decisionForm.addEventListener(
        "submit",
        async event => {
            event.preventDefault();

            const admin = adminInput.value.trim();
            const reason = reasonInput.value.trim();

            if (!admin) {
                errorBox.textContent = (
                    "Administrator name is required."
                );

                errorBox.hidden = false;
                adminInput.focus();
                return;
            }

            if (reason.length < 8) {
                errorBox.textContent = (
                    "Decision reason must contain at least 8 characters."
                );

                errorBox.hidden = false;
                reasonInput.focus();
                return;
            }

            errorBox.hidden = true;
            submitButton.disabled = true;
            submitButton.classList.add("loading");

            const endpoint = (
                `/api/gateway/approvals/`
                + `${encodeURIComponent(state.decisionId)}/`
                + `${state.action}`
                + `?admin=${encodeURIComponent(admin)}`
                + `&reason=${encodeURIComponent(reason)}`
            );

            try {
                const response = await fetch(
                    endpoint,
                    {
                        method: "POST",
                        headers: {
                            Accept: "application/json",
                        },
                    },
                );

                if (!response.ok) {
                    const payload = await response
                        .json()
                        .catch(() => ({}));

                    throw new Error(
                        payload.detail
                        || `HTTP ${response.status}`,
                    );
                }

                await response.json();

                const actionLabel = (
                    state.action === "approve"
                        ? "approved"
                        : "rejected"
                );

                closeDialog();

                notify(
                    `Command ${actionLabel} successfully`,
                );

                window.setTimeout(() => {
                    window.location.reload();
                }, 700);
            } catch (error) {
                errorBox.textContent = (
                    `Unable to save decision: ${escapeHtml(error.message)}`
                );

                errorBox.hidden = false;
            } finally {
                submitButton.disabled = false;
                submitButton.classList.remove(
                    "loading",
                );
            }
        },
    );

    closeButton.addEventListener(
        "click",
        closeDialog,
    );

    cancelButton.addEventListener(
        "click",
        closeDialog,
    );

    overlay.addEventListener(
        "click",
        event => {
            if (event.target === overlay) {
                closeDialog();
            }
        },
    );

    document.addEventListener(
        "keydown",
        event => {
            if (
                event.key === "Escape"
                && !overlay.hidden
            ) {
                closeDialog();
            }
        },
    );
})();
