(() => {
    const normalize = value => String(value || "").trim().toLowerCase();
    const byId = id => document.getElementById(id);

    const escapeHtml = value => String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

    const fetchJson = async path => {
        const response = await fetch(path, {
            headers: {
                Accept: "application/json",
            },
            cache: "no-store",
        });

        if (!response.ok) {
            throw new Error(`${path}: ${response.status}`);
        }

        return response.json();
    };

    const applyTableFilters = container => {
        const searchInput = container.querySelector("[data-table-search]");
        const filters = [...container.querySelectorAll("[data-table-filter]")];
        const rows = [...container.querySelectorAll("[data-table-row]")];
        const empty = container.querySelector("[data-table-empty]");
        const search = normalize(searchInput?.value);

        let visible = 0;

        rows.forEach(row => {
            const searchable = normalize(
                row.dataset.search || row.textContent,
            );

            const matchesSearch = !search || searchable.includes(search);

            const matchesFilters = filters.every(filter => {
                const value = normalize(filter.value);

                if (!value) {
                    return true;
                }

                const key = filter.dataset.tableFilter;
                return normalize(row.dataset[key]) === value;
            });

            const show = matchesSearch && matchesFilters;

            row.hidden = !show;

            if (show) {
                visible += 1;
            }
        });

        if (empty) {
            empty.hidden = visible > 0;
        }
    };

    const initializeTables = () => {
        const containers = [
            ...document.querySelectorAll("[data-table-container]"),
        ];

        const urlSearch = new URLSearchParams(
            window.location.search,
        ).get("search") || "";

        containers.forEach(container => {
            const inputs = [
                ...container.querySelectorAll(
                    "[data-table-search], [data-table-filter]",
                ),
            ];

            const localSearch = container.querySelector(
                "[data-table-search]",
            );

            if (localSearch && urlSearch) {
                localSearch.value = urlSearch;
            }

            inputs.forEach(input => {
                input.addEventListener(
                    input.matches("select") ? "change" : "input",
                    () => applyTableFilters(container),
                );
            });

            applyTableFilters(container);
        });

        const globalSearch = document.querySelector(
            ".topbar-search input",
        );

        const localSearch = document.querySelector(
            "[data-table-search]",
        );

        if (globalSearch && urlSearch) {
            globalSearch.value = urlSearch;
        }

        if (globalSearch && localSearch) {
            globalSearch.addEventListener("input", () => {
                localSearch.value = globalSearch.value;
                localSearch.dispatchEvent(
                    new Event("input", { bubbles: true }),
                );
            });

            localSearch.addEventListener("input", () => {
                globalSearch.value = localSearch.value;
            });
        }

        globalSearch?.addEventListener("keydown", event => {
            if (event.key !== "Enter") {
                return;
            }

            const query = globalSearch.value.trim();

            if (!query) {
                return;
            }

            if (!localSearch) {
                window.location.href = `/runs?search=${encodeURIComponent(query)}`;
            }
        });

        document.addEventListener("keydown", event => {
            if (
                event.key === "/"
                && document.activeElement?.tagName !== "INPUT"
                && document.activeElement?.tagName !== "TEXTAREA"
            ) {
                event.preventDefault();
                globalSearch?.focus();
            }
        });
    };

    const initializeRefresh = () => {
        document
            .querySelectorAll("[data-page-refresh]")
            .forEach(button => {
                button.addEventListener("click", () => {
                    button.disabled = true;
                    window.location.reload();
                });
            });
    };

    const initializeConfirmations = () => {
        document
            .querySelectorAll("form[data-confirm]")
            .forEach(form => {
                form.addEventListener("submit", event => {
                    const message = form.dataset.confirm;

                    if (!window.confirm(message)) {
                        event.preventDefault();
                    }
                });
            });
    };

    const timeAgo = value => {
        if (!value) {
            return "Stored";
        }

        const date = new Date(value);

        if (Number.isNaN(date.getTime())) {
            return "Stored";
        }

        const seconds = Math.max(
            0,
            Math.floor(
                (Date.now() - date.getTime()) / 1000,
            ),
        );

        if (seconds < 60) {
            return `${seconds}s ago`;
        }

        if (seconds < 3600) {
            return `${Math.floor(seconds / 60)}m ago`;
        }

        if (seconds < 86400) {
            return `${Math.floor(seconds / 3600)}h ago`;
        }

        return `${Math.floor(seconds / 86400)}d ago`;
    };

    const decisionTone = value => {
        const decision = normalize(value);

        if (
            decision.includes("block")
            || decision.includes("deny")
        ) {
            return "notification-critical";
        }

        if (
            decision.includes("review")
            || decision.includes("confirm")
        ) {
            return "notification-warning";
        }

        return "notification-safe";
    };

    const renderNotifications = async () => {
        const list = byId("notificationList");

        try {
            const [stats, decisions] = await Promise.all([
                fetchJson("/api/stats"),
                fetchJson("/api/gateway/decisions"),
            ]);

            const alertCount = Number(stats.alerts || 0);
            const pendingCount = Number(
                stats.pending_approvals || 0,
            );

            const badge = byId("notificationBadge");

            if (badge) {
                badge.textContent = alertCount;
                badge.hidden = alertCount === 0;
            }

            if (byId("notificationTotal")) {
                byId("notificationTotal").textContent = alertCount;
            }

            if (byId("notificationPending")) {
                byId("notificationPending").textContent = pendingCount;
            }

            if (!list) {
                return;
            }

            const records = Array.isArray(decisions)
                ? decisions.slice(0, 8)
                : [];

            if (!records.length) {
                list.innerHTML = `
                    <div class="drawer-empty">
                        <strong>No gateway events</strong>
                        <span>No recent security decision is available.</span>
                    </div>
                `;
                return;
            }

            list.innerHTML = records.map(item => {
                const decision = escapeHtml(
                    item.security_decision
                    || item.decision
                    || "Security decision",
                );

                const command = escapeHtml(
                    item.command_text
                    || item.command
                    || "Unknown command",
                );

                const risk = escapeHtml(
                    item.risk_level || "unknown",
                );

                return `
                    <a class="notification-item" href="/runs">
                        <i class="${decisionTone(decision)}"></i>
                        <div>
                            <strong>${decision}</strong>
                            <code title="${command}">${command}</code>
                            <span>${risk} risk · ${timeAgo(item.created_at)}</span>
                        </div>
                    </a>
                `;
            }).join("");
        } catch (error) {
            if (list) {
                list.innerHTML = `
                    <div class="drawer-empty">
                        <strong>Unable to load notifications</strong>
                        <span>${escapeHtml(error.message)}</span>
                    </div>
                `;
            }
        }
    };

    const initializeShell = () => {
        const backdrop = byId("uiBackdrop");
        const notificationDrawer = byId("notificationDrawer");
        const notificationButton = byId("notificationsButton");
        const notificationClose = byId("notificationClose");
        const helpButton = byId("helpButton");
        const helpModal = byId("helpModal");
        const helpClose = byId("helpClose");
        const userButton = byId("userMenuButton");
        const userPopover = byId("userPopover");

        const closeAll = () => {
            notificationDrawer?.classList.remove("open");

            if (notificationDrawer) {
                notificationDrawer.setAttribute(
                    "aria-hidden",
                    "true",
                );
            }

            if (helpModal) {
                helpModal.hidden = true;
            }

            if (userPopover) {
                userPopover.hidden = true;
            }

            if (userButton) {
                userButton.setAttribute(
                    "aria-expanded",
                    "false",
                );
            }

            if (backdrop) {
                backdrop.hidden = true;
            }

            document.body.classList.remove("ui-locked");
        };

        const openNotifications = async () => {
            closeAll();

            if (notificationDrawer) {
                notificationDrawer.classList.add("open");
                notificationDrawer.setAttribute(
                    "aria-hidden",
                    "false",
                );
            }

            if (backdrop) {
                backdrop.hidden = false;
            }

            document.body.classList.add("ui-locked");

            await renderNotifications();
        };

        const openHelp = () => {
            closeAll();

            if (helpModal) {
                helpModal.hidden = false;
            }

            if (backdrop) {
                backdrop.hidden = false;
            }

            document.body.classList.add("ui-locked");
        };

        const toggleUser = () => {
            const willOpen = userPopover?.hidden ?? false;

            closeAll();

            if (!willOpen || !userPopover || !userButton) {
                return;
            }

            const rect = userButton.getBoundingClientRect();

            userPopover.style.top = `${rect.bottom + 10}px`;
            userPopover.style.right = `${Math.max(
                14,
                window.innerWidth - rect.right,
            )}px`;

            userPopover.hidden = false;

            userButton.setAttribute(
                "aria-expanded",
                "true",
            );
        };

        notificationButton?.addEventListener(
            "click",
            openNotifications,
        );

        notificationClose?.addEventListener(
            "click",
            closeAll,
        );

        helpButton?.addEventListener(
            "click",
            openHelp,
        );

        helpClose?.addEventListener(
            "click",
            closeAll,
        );

        userButton?.addEventListener(
            "click",
            toggleUser,
        );

        backdrop?.addEventListener(
            "click",
            closeAll,
        );

        document.addEventListener("keydown", event => {
            if (event.key === "Escape") {
                closeAll();
            }
        });

        renderNotifications();

        window.setInterval(
            renderNotifications,
            30000,
        );
    };

    initializeTables();
    initializeRefresh();
    initializeConfirmations();
    initializeShell();
})();
