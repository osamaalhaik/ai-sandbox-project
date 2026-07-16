(() => {
    const state = {
        stats: {},
        runs: [],
        gateway: [],
        pending: [],
        approvals: [],
        filteredRuns: [],
        period: "24h",
        search: "",
        status: "",
        risk: "",
    };

    const byId = id => document.getElementById(id);

    const escapeHtml = value => String(value ?? "")
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");

    const toNumber = value => {
        const parsed = Number(value);
        return Number.isFinite(parsed) ? parsed : 0;
    };

    const percent = (value, total) => {
        if (!total) return 0;
        return Math.round((value / total) * 1000) / 10;
    };

    const parseDate = value => {
        if (!value) return null;
        const date = new Date(value);
        return Number.isNaN(date.getTime()) ? null : date;
    };

    const periodStart = period => {
        const now = Date.now();

        if (period === "24h") return new Date(now - 24 * 60 * 60 * 1000);
        if (period === "7d") return new Date(now - 7 * 24 * 60 * 60 * 1000);
        if (period === "30d") return new Date(now - 30 * 24 * 60 * 60 * 1000);

        return null;
    };

    const timeAgo = value => {
        const date = parseDate(value);

        if (!date) return "Stored";

        const seconds = Math.max(
            0,
            Math.floor((Date.now() - date.getTime()) / 1000),
        );

        if (seconds < 60) return `${seconds}s ago`;
        if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
        if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
        if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;

        return date.toLocaleDateString();
    };

    const periodLabel = value => {
        if (value === "24h") return "Last 24 hours";
        if (value === "7d") return "Last 7 days";
        if (value === "30d") return "Last 30 days";
        return "All records";
    };

    const riskClass = risk => {
        const normalized = String(risk || "").toLowerCase();

        if (normalized === "critical") return "risk-critical";
        if (normalized === "high") return "risk-high";
        if (normalized === "suspicious") return "risk-medium";

        return "risk-low";
    };

    const decisionClass = decision => {
        const normalized = String(decision || "").toLowerCase();

        if (
            normalized.includes("block")
            || normalized.includes("deny")
        ) {
            return "status-block";
        }

        if (
            normalized.includes("review")
            || normalized.includes("confirm")
        ) {
            return "status-review";
        }

        return "status-allow";
    };

    const activityClass = item => {
        const risk = String(
            item.risk_level || item.level || "",
        ).toLowerCase();

        if (risk === "critical" || risk === "high") {
            return "activity-critical";
        }

        if (risk === "suspicious" || risk === "medium") {
            return "activity-medium";
        }

        return "activity-safe";
    };

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

    const setText = (id, value) => {
        const element = byId(id);
        if (element) element.textContent = value;
    };

    const setWidth = (id, value) => {
        const element = byId(id);
        if (element) element.style.width = `${Math.max(0, Math.min(100, value))}%`;
    };

    const filteredByPeriod = runs => {
        const start = periodStart(state.period);

        if (!start) return [...runs];

        return runs.filter(run => {
            const date = parseDate(run.created_at);
            return !date || date >= start;
        });
    };

    const applyFilters = () => {
        const query = state.search.trim().toLowerCase();

        state.filteredRuns = filteredByPeriod(state.runs)
            .filter(run => {
                const searchable = [
                    run.run_id,
                    run.command,
                    run.executable,
                    run.status,
                    run.risk_level,
                    run.decision,
                ]
                    .join(" ")
                    .toLowerCase();

                if (query && !searchable.includes(query)) {
                    return false;
                }

                if (
                    state.status
                    && String(run.status || "").toLowerCase()
                        !== state.status
                ) {
                    return false;
                }

                if (
                    state.risk
                    && String(run.risk_level || "").toLowerCase()
                        !== state.risk
                ) {
                    return false;
                }

                return true;
            });

        renderDashboard();
    };

    const renderMetrics = () => {
        const stats = state.stats;
        const total = toNumber(stats.total_runs);
        const allowed = toNumber(stats.allowed);
        const reviewed = toNumber(stats.reviewed);
        const blocked = toNumber(stats.blocked_or_investigate);

        setText("metricTotal", total);
        setText("metricAllowed", allowed);
        setText("metricReview", reviewed);
        setText("metricBlocked", blocked);

        setText("metricTotalRate", total ? "100%" : "0%");
        setText("metricAllowedRate", `${percent(allowed, total)}%`);
        setText("metricReviewRate", `${percent(reviewed, total)}%`);
        setText("metricBlockedRate", `${percent(blocked, total)}%`);

        setText(
            "gatewayDecisionCount",
            `${toNumber(stats.total_gateway_decisions)} gateway decisions`,
        );

        setText("postureCritical", toNumber(stats.critical_blocks));
        setText("posturePending", toNumber(stats.pending_approvals));
        setText("postureRejected", toNumber(stats.rejected_commands));

        setText("stripGateway", toNumber(stats.total_gateway_decisions));
        setText("stripPending", toNumber(stats.pending_approvals));
        setText("stripRejected", toNumber(stats.rejected_commands));
        setText("stripCritical", toNumber(stats.critical_blocks));

        const alertBadge = document.querySelector(
            'a[href="/alerts"] em',
        );

        const approvalBadge = document.querySelector(
            'a[href="/approvals"] em',
        );

        if (alertBadge) {
            alertBadge.textContent = toNumber(stats.alerts);
        }

        if (approvalBadge) {
            approvalBadge.textContent = toNumber(
                stats.pending_approvals,
            );
        }
    };

    const renderRisk = () => {
        const runs = filteredByPeriod(state.runs);

        const counts = {
            critical: 0,
            high: 0,
            suspicious: 0,
            low: 0,
        };

        runs.forEach(run => {
            const key = String(
                run.risk_level || "low",
            ).toLowerCase();

            if (Object.hasOwn(counts, key)) {
                counts[key] += 1;
            } else {
                counts.low += 1;
            }
        });

        const total = Object.values(counts)
            .reduce((sum, count) => sum + count, 0);

        setText("riskTotal", total);
        setText("riskCritical", counts.critical);
        setText("riskHigh", counts.high);
        setText("riskSuspicious", counts.suspicious);
        setText("riskLow", counts.low);

        const donut = byId("riskDonut");

        if (donut) {
            donut.style.setProperty(
                "--critical",
                percent(counts.critical, total),
            );

            donut.style.setProperty(
                "--high",
                percent(counts.high, total),
            );

            donut.style.setProperty(
                "--medium",
                percent(counts.suspicious, total),
            );

            donut.style.setProperty(
                "--low",
                percent(counts.low, total),
            );
        }
    };

    const renderDecisions = () => {
        const runs = filteredByPeriod(state.runs);

        const decisions = {
            allow: 0,
            review: 0,
            confirm: 0,
            block: 0,
        };

        runs.forEach(run => {
            const decision = String(
                run.decision || "",
            ).toLowerCase();

            if (
                decision === "allow"
                || decision === "allow_with_monitoring"
            ) {
                decisions.allow += 1;
            } else if (decision === "review") {
                decisions.review += 1;
            } else if (decision.includes("confirm")) {
                decisions.confirm += 1;
            } else if (
                decision.includes("block")
                || decision.includes("deny")
            ) {
                decisions.block += 1;
            }
        });

        const total = Object.values(decisions)
            .reduce((sum, count) => sum + count, 0);

        setText("decisionAllow", decisions.allow);
        setText("decisionReview", decisions.review);
        setText("decisionConfirm", decisions.confirm);
        setText("decisionBlock", decisions.block);

        setWidth(
            "decisionAllowBar",
            percent(decisions.allow, total),
        );

        setWidth(
            "decisionReviewBar",
            percent(decisions.review, total),
        );

        setWidth(
            "decisionConfirmBar",
            percent(decisions.confirm, total),
        );

        setWidth(
            "decisionBlockBar",
            percent(decisions.block, total),
        );
    };

    const renderTable = () => {
        const body = byId("decisionsBody");
        const empty = byId("decisionEmpty");

        if (!body) return;

        const rows = state.filteredRuns
            .slice(0, 50)
            .map(run => {
                const id = escapeHtml(run.run_id || "");
                const command = escapeHtml(run.command || "");
                const executable = escapeHtml(run.executable || "—");
                const risk = escapeHtml(run.risk_level || "low");
                const score = toNumber(run.risk_score);
                const decision = escapeHtml(run.decision || "unknown");
                const status = escapeHtml(run.status || "unknown");

                return `
                    <tr>
                        <td>
                            <code title="${command}">${command}</code>
                            <small>${id.slice(0, 12)}…</small>
                        </td>
                        <td>${executable}</td>
                        <td>
                            <span class="risk-badge ${riskClass(risk)}">
                                ${score} · ${risk}
                            </span>
                        </td>
                        <td>
                            <span class="status-badge ${decisionClass(decision)}">
                                ${decision}
                            </span>
                        </td>
                        <td>${status}</td>
                        <td>${timeAgo(run.created_at)}</td>
                        <td>
                            <a class="row-action" href="/runs/${id}">
                                View
                            </a>
                        </td>
                    </tr>
                `;
            })
            .join("");

        body.innerHTML = rows;

        if (empty) {
            empty.hidden = state.filteredRuns.length > 0;
        }
    };

    const renderActivity = () => {
        const host = byId("activityList");

        if (!host) return;

        const gatewayItems = [...state.gateway]
            .sort((a, b) => {
                const dateA = parseDate(a.created_at)?.getTime() || 0;
                const dateB = parseDate(b.created_at)?.getTime() || 0;
                return dateB - dateA;
            })
            .slice(0, 4);

        const source = gatewayItems.length
            ? gatewayItems
            : filteredByPeriod(state.runs).slice(0, 4);

        host.innerHTML = source.map(item => {
            const title = escapeHtml(
                item.security_decision
                || item.decision
                || item.status
                || "Security event",
            );

            const command = escapeHtml(
                item.command_text
                || item.command
                || "Unknown command",
            );

            return `
                <div>
                    <i class="${activityClass(item)}"></i>
                    <p>
                        <strong>${title}</strong>
                        <span title="${command}">${command}</span>
                    </p>
                    <time>${timeAgo(item.created_at)}</time>
                </div>
            `;
        }).join("");
    };

    const chartBuckets = runs => {
        const source = filteredByPeriod(runs);
        const bucketCount = 12;

        if (!source.length) {
            return Array(bucketCount).fill(0);
        }

        const dates = source
            .map(run => parseDate(run.created_at))
            .filter(Boolean);

        if (!dates.length) {
            const values = Array(bucketCount).fill(0);

            source.forEach((run, index) => {
                values[index % bucketCount] += 1;
            });

            return values;
        }

        const timestamps = dates.map(date => date.getTime());
        const minimum = Math.min(...timestamps);
        const maximum = Math.max(...timestamps);
        const range = Math.max(1, maximum - minimum);
        const values = Array(bucketCount).fill(0);

        timestamps.forEach(timestamp => {
            const index = Math.min(
                bucketCount - 1,
                Math.floor(
                    ((timestamp - minimum) / range)
                    * bucketCount,
                ),
            );

            values[index] += 1;
        });

        return values;
    };

    const renderChart = () => {
        const host = byId("executionChart");

        if (!host) return;

        const values = chartBuckets(state.runs);
        const width = 720;
        const height = 220;
        const paddingX = 34;
        const paddingY = 24;
        const maximum = Math.max(1, ...values);
        const step = (
            width - paddingX * 2
        ) / Math.max(1, values.length - 1);

        const pointY = value => (
            height
            - paddingY
            - (value / maximum)
            * (height - paddingY * 2)
        );

        const points = values
            .map((value, index) => (
                `${paddingX + index * step},${pointY(value)}`
            ))
            .join(" ");

        const areaPoints = [
            `${paddingX},${height - paddingY}`,
            points,
            `${width - paddingX},${height - paddingY}`,
        ].join(" ");

        const grid = [0, 1, 2, 3, 4]
            .map(index => {
                const y = (
                    paddingY
                    + index
                    * ((height - paddingY * 2) / 4)
                );

                return `
                    <line
                        x1="${paddingX}"
                        y1="${y}"
                        x2="${width - paddingX}"
                        y2="${y}"
                        stroke="#dfe6ef"
                        stroke-width="1"
                    />
                `;
            })
            .join("");

        const circles = values
            .map((value, index) => `
                <circle
                    cx="${paddingX + index * step}"
                    cy="${pointY(value)}"
                    r="3.5"
                    fill="#ffffff"
                    stroke="#2563eb"
                    stroke-width="2"
                />
            `)
            .join("");

        host.innerHTML = `
            <svg
                viewBox="0 0 ${width} ${height}"
                preserveAspectRatio="none"
                aria-label="Execution activity chart"
            >
                <defs>
                    <linearGradient
                        id="executionArea"
                        x1="0"
                        y1="0"
                        x2="0"
                        y2="1"
                    >
                        <stop
                            offset="0%"
                            stop-color="#2563eb"
                            stop-opacity=".24"
                        />
                        <stop
                            offset="100%"
                            stop-color="#2563eb"
                            stop-opacity="0"
                        />
                    </linearGradient>
                </defs>

                ${grid}

                <polygon
                    points="${areaPoints}"
                    fill="url(#executionArea)"
                />

                <polyline
                    points="${points}"
                    fill="none"
                    stroke="#2563eb"
                    stroke-width="4"
                    stroke-linecap="round"
                    stroke-linejoin="round"
                />

                ${circles}
            </svg>
        `;
    };

    const renderDashboard = () => {
        renderMetrics();
        renderRisk();
        renderDecisions();
        renderTable();
        renderActivity();
        renderChart();

        setText(
            "activityWindowLabel",
            periodLabel(state.period),
        );

        setText(
            "lastUpdated",
            `Updated ${new Date().toLocaleTimeString()}`,
        );
    };

    const loadDashboard = async () => {
        const refreshButton = byId("dashboardRefresh");

        if (refreshButton) {
            refreshButton.disabled = true;
            refreshButton.classList.add("refreshing");
        }

        try {
            const [
                stats,
                runs,
                gateway,
                pending,
                approvals,
            ] = await Promise.all([
                fetchJson("/api/stats"),
                fetchJson("/api/runs"),
                fetchJson("/api/gateway/decisions"),
                fetchJson("/api/gateway/pending"),
                fetchJson("/api/gateway/approvals"),
            ]);

            state.stats = stats || {};
            state.runs = Array.isArray(runs) ? runs : [];
            state.gateway = Array.isArray(gateway) ? gateway : [];
            state.pending = Array.isArray(pending) ? pending : [];
            state.approvals = Array.isArray(approvals)
                ? approvals
                : [];

            applyFilters();
        } catch (error) {
            console.error(error);

            setText(
                "lastUpdated",
                "Live update failed",
            );
        } finally {
            if (refreshButton) {
                refreshButton.disabled = false;
                refreshButton.classList.remove("refreshing");
            }
        }
    };

    const bindControls = () => {
        const refresh = byId("dashboardRefresh");
        const period = byId("periodFilter");
        const search = byId("decisionSearch");
        const status = byId("statusFilter");
        const risk = byId("riskFilter");
        const globalSearch = document.querySelector(
            ".topbar-search input",
        );
        const menu = byId("mobileMenu");
        const sidebar = byId("sidebar");

        refresh?.addEventListener("click", loadDashboard);

        period?.addEventListener("change", event => {
            state.period = event.target.value;
            applyFilters();
        });

        search?.addEventListener("input", event => {
            state.search = event.target.value;

            if (globalSearch) {
                globalSearch.value = state.search;
            }

            applyFilters();
        });

        globalSearch?.addEventListener("input", event => {
            state.search = event.target.value;

            if (search) {
                search.value = state.search;
            }

            applyFilters();
        });

        status?.addEventListener("change", event => {
            state.status = event.target.value;
            applyFilters();
        });

        risk?.addEventListener("change", event => {
            state.risk = event.target.value;
            applyFilters();
        });

        menu?.addEventListener("click", () => {
            sidebar?.classList.toggle("open");
        });
    };

    if (!byId("dashboardRefresh")) {
        return;
    }

    bindControls();

    if (byId("dashboardRefresh")) {
        loadDashboard();

        window.setInterval(
            loadDashboard,
            30000,
        );
    }
})();
