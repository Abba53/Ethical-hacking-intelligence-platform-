import asyncio
import json
import os
from dotenv import load_dotenv

load_dotenv(
    "/data/data/com.termux/files/home/ethical-hacking-intel-platform/.env"
)

from analysis.ai_analysis import AIAnalyst


PASS = 0
FAIL = 0


def result_ok(result):
    return getattr(result, "success", False) is True


def check(label, condition, detail=""):
    global PASS, FAIL

    if condition:
        PASS += 1
        print(f"[PASS] {label}")
        if detail:
            print(f"       {detail}")
    else:
        FAIL += 1
        print(f"[FAIL] {label}")
        if detail:
            print(f"       {detail}")


async def test_executive_summary(ai):
    print("\n=== TEST 7: executive_summary ===")

    result = await ai.executive_summary(
        report={
            "target": "example.com",
            "critical_findings": 2,
            "high_findings": 5,
            "medium_findings": 8,
            "low_findings": 3,
            "domains": 4,
            "open_ports": [22, 80, 443],
            "security_domains": [
                "web",
                "network",
                "api",
            ],
        }
    )

    print(result)

    check(
        "executive_summary success",
        result_ok(result),
        f"provider={getattr(result, 'provider', None)}",
    )

    check(
        "executive_summary report type",
        getattr(result, "report_type", None) == "executive",
        f"report_type={getattr(result, 'report_type', None)}",
    )

    check(
        "executive_summary has analysis",
        getattr(result, "analysis", None) is not None,
    )

    check(
        "executive_summary execution time",
        getattr(result, "execution_time_ms", 0) > 0,
        f"execution_time_ms={getattr(result, 'execution_time_ms', None)}",
    )


async def test_campaign(ai):
    print("\n=== TEST 8: analyze_campaign ===")

    method = getattr(ai, "analyze_campaign", None)

    if method is None:
        print("[SKIP] analyze_campaign() is not implemented.")
        return

    result = await method(
        campaign={
            "iocs": [
                {
                    "type": "ipv4",
                    "value": "198.51.100.10",
                },
                {
                    "type": "domain",
                    "value": "example-threat.test",
                },
                {
                    "type": "sha256",
                    "value": "deadbeef" * 8,
                },
            ]
        }
    )

    print(result)

    check(
        "analyze_campaign success",
        result_ok(result),
    )


async def test_provider_health(ai):
    print("\n=== TEST 9: provider health ===")

    provider = ai.provider

    health_method = getattr(provider, "health_check", None)

    if health_method is None:
        print("[SKIP] provider.health_check() is not implemented.")
        return

    try:
        health = await health_method()

        print("Health:", health)

        check(
            "provider health check",
            health is True,
        )

    except Exception as exc:
        check(
            "provider health check",
            False,
            f"{type(exc).__name__}: {exc}",
        )


async def test_response_structure(ai):
    print("\n=== TEST 10: response structure ===")

    result = await ai.analyze_network(
        target="198.51.100.10",
        data={
            "asn": "AS64500",
            "org": "TEST-NET",
            "country": "ZZ",
            "open_ports": [443],
        },
    )

    print(result)

    required = [
        "success",
        "provider",
        "report_type",
        "analysis",
        "raw_response",
        "error",
        "execution_time_ms",
    ]

    for field in required:
        check(
            f"AIResponse field: {field}",
            hasattr(result, field),
        )

    check(
        "response success",
        result_ok(result),
    )

    check(
        "response has raw_response",
        bool(getattr(result, "raw_response", "")),
    )


async def test_provider_identity(ai):
    print("\n=== TEST 11: provider identity ===")

    provider = ai.provider

    print("Provider:", provider)
    print("Name:", getattr(provider, "provider_name", None))
    print("Model:", getattr(provider, "model_name", None))

    check(
        "provider name exists",
        bool(getattr(provider, "provider_name", None)),
    )

    check(
        "provider model exists",
        bool(getattr(provider, "model_name", None)),
    )


async def test_error_handling(ai):
    print("\n=== TEST 12: malformed input/error handling ===")

    try:
        result = await ai.analyze_network(
            target="test.invalid",
            data={
                "unexpected": object(),
            },
        )

        print(result)

        check(
            "malformed input does not crash process",
            result is not None,
        )

    except Exception as exc:
        print(
            f"Caught: {type(exc).__name__}: {exc}"
        )

        check(
            "malformed input handled",
            False,
        )


async def main():
    print("=" * 60)
    print("PHASE 11 — REMAINING TESTS")
    print("=" * 60)

    ai = AIAnalyst()

    print("\nProvider in use:")
    print(ai.provider)

    await test_executive_summary(ai)
    await test_campaign(ai)
    await test_provider_health(ai)
    await test_response_structure(ai)
    await test_provider_identity(ai)
    await test_error_handling(ai)

    print("\n" + "=" * 60)
    print("PHASE 11 TEST SUMMARY")
    print("=" * 60)
    print(f"PASS: {PASS}")
    print(f"FAIL: {FAIL}")

    if FAIL == 0:
        print("\nRESULT: ALL EXECUTED TESTS PASSED")
    else:
        print("\nRESULT: FAILURES DETECTED")

    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
