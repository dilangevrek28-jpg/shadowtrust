import { afterEach, describe, expect, it, vi } from "vitest";
import {
  getDecision,
  getSessionRisks,
  openCase,
  replayDecision,
  ShadowTrustApiError
} from "./client";

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("ShadowTrust API client", () => {
  it("sends the analyst key and serializes queue filters", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ page: 2, page_size: 25, total: 0, items: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    await getSessionRisks("analyst-secret", {
      minimumRisk: 70,
      riskLevel: "critical",
      caseStatus: "investigating",
      page: 2,
      pageSize: 25
    });

    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toContain("minimum_risk=70");
    expect(url).toContain("risk_level=critical");
    expect(url).toContain("page=2");
    expect(url).toContain("case_status=investigating");
    expect(options.headers["X-Analyst-API-Key"]).toBe("analyst-secret");
  });

  it("maps the structured backend error without exposing arbitrary response text", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            error: { code: "analyst_api_key_invalid", message: "The analyst API key is invalid." }
          }),
          { status: 403, headers: { "Content-Type": "application/json" } }
        )
      )
    );

    await expect(getDecision("wrong-key", "decision-id")).rejects.toEqual(
      new ShadowTrustApiError("The analyst API key is invalid.", 403, "analyst_api_key_invalid")
    );
  });

  it("sends analyst identity and JSON body for case mutations", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ id: "case-id" }), {
        status: 201,
        headers: { "Content-Type": "application/json" }
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    await openCase("analyst-secret", "analyst.one", "session-id", "Review transfer.");

    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toContain("/api/v1/analyst/cases");
    expect(options.method).toBe("POST");
    expect(options.headers["X-Analyst-API-Key"]).toBe("analyst-secret");
    expect(options.headers["X-Analyst-ID"]).toBe("analyst.one");
    expect(JSON.parse(options.body)).toEqual({
      session_id: "session-id",
      note: "Review transfer."
    });
  });

  it("replays a decision with analyst authorization and POST", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ status: "reproduced", differences: [] }), {
        status: 200,
        headers: { "Content-Type": "application/json" }
      })
    );
    vi.stubGlobal("fetch", fetchMock);

    await replayDecision("analyst-secret", "decision-id");

    const [url, options] = fetchMock.mock.calls[0];
    expect(url).toContain("/api/v1/analyst/decisions/decision-id/replay");
    expect(options.method).toBe("POST");
    expect(options.headers["X-Analyst-API-Key"]).toBe("analyst-secret");
    expect(options.headers["X-Analyst-ID"]).toBeUndefined();
  });
});
