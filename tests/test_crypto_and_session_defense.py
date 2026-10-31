"""
FinCipher AI — Crypto Address Poisoning, Counter-Trading Siphon & Session-Device Defense Tests
Author: Om Kamble

Verifies defensive hardening against real-world crypto exchange exploits:
1. Zero-value address poisoning & lookalike vanity address spoofing ($68M+ whale attack pattern)
2. Illiquid pair pump-and-dump cross-trading / counter-trading drain (AggrTrade Trojan extension pattern)
3. Cryptographic token-device fingerprint binding to prevent stolen cookie / JWT session replay
4. API endpoints and dynamic rules engine integration
"""

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.engine.threat_intelligence import ThreatIntelligenceEngine
from src.engine.rules import HybridRuleEngine, ActionDecision
from src.core.security import (
    create_access_token,
    decode_jwt_token,
    generate_device_fingerprint_hash,
    verify_token_device_binding
)

client = TestClient(app)
threat_intel = ThreatIntelligenceEngine()


# =============================================================================
# 1. CRYPTO ADDRESS POISONING & LOOKALIKE VANITY ADDRESS SPOOFING
# =============================================================================

def test_crypto_address_poisoning_authentic_beneficiary_allowed():
    """Confirms that transactions to exact authentic beneficiaries are permitted without false alarms."""
    authentic_beneficiary = "0x71C836e1b6B10959A65D8291f0C6559815049B4A"
    res = threat_intel.evaluate_crypto_address_poisoning(
        target_address=authentic_beneficiary,
        known_beneficiaries=[authentic_beneficiary],
        amount=1500.0,
        is_zero_value_dust=False
    )
    assert res.is_address_poisoning_detected is False
    assert res.threat_score < 0.20
    assert res.lookalike_matched_beneficiary is None


def test_crypto_address_poisoning_vanity_clone_detected():
    """
    Simulates the $68M WBTC poisoning attack:
    Attacker creates a vanity address with identical prefix (0x71c83) and suffix (49b4a)
    but completely divergent middle entropy.
    """
    authentic_beneficiary = "0x71c836e1b6b10959a65d8291f0c6559815049b4a"
    # Poisoned lookalike address (same first 7 and last 5 hex characters)
    poisoned_clone = "0x71c8399999999999999999999999999999049b4a"

    res = threat_intel.evaluate_crypto_address_poisoning(
        target_address=poisoned_clone,
        known_beneficiaries=[authentic_beneficiary],
        amount=50000.0,
        is_zero_value_dust=False,
        prefix_len=5,
        suffix_len=5
    )

    assert res.is_address_poisoning_detected is True
    assert res.threat_score >= 0.90
    assert res.lookalike_matched_beneficiary == authentic_beneficiary
    assert res.prefix_match == "71c83"
    assert res.suffix_match == "49b4a"
    assert res.middle_entropy_divergence >= 0.50
    assert any("ADDRESS_POISONING_VANITY_SPOOF" in r for r in res.reasons)


def test_crypto_address_poisoning_zero_value_dust_attack():
    """Verifies that 0-value dust transactions designed to pollute address history are flagged."""
    untrusted_address = "0x0000000000000000000000000000000000deadbeef"
    res = threat_intel.evaluate_crypto_address_poisoning(
        target_address=untrusted_address,
        amount=0.00001,
        is_zero_value_dust=True
    )
    assert res.is_dust_attack is True
    assert res.threat_score >= 0.40
    assert any("ZERO_VALUE_DUST_INJECTION" in r for r in res.reasons)


def test_crypto_address_poisoning_api_endpoint():
    """Tests the /api/v1/crypto/address-poisoning-check endpoint logic."""
    from src.api.main import api_address_poisoning_check, AddressPoisoningCheckRequest

    authentic = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045"
    spoofed = "0xd8da6aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa96045"

    req = AddressPoisoningCheckRequest(
        target_address=spoofed,
        known_beneficiaries=[authentic],
        amount=25000.0,
        is_zero_value_dust=False
    )
    data = api_address_poisoning_check(req)
    assert data["is_address_poisoning_detected"] is True
    assert data["threat_score"] >= 0.90
    assert data["lookalike_matched_beneficiary"] == authentic


# =============================================================================
# 2. ILLIQUID COUNTER-TRADING & SLIPPAGE SIPHON SENTINEL
# =============================================================================

def test_counter_trading_standard_nominal_trade():
    """Confirms legitimate market trading with tight spreads is permitted."""
    res = threat_intel.evaluate_counter_trading_anomaly(
        symbol="BTC/USDT",
        trade_type="BUY",
        volume=0.5,
        execution_price=64200.0,
        reference_index_price=64180.0,
        order_book_depth_usd=5000000.0
    )
    assert res.is_counter_trading_detected is False
    assert res.price_divergence_pct < 1.0
    assert res.threat_score < 0.20
    assert res.recommended_action == "FRICTIONLESS_ALLOW"


def test_counter_trading_severe_illiquid_siphon_drain():
    """
    Simulates the AggrTrade malicious Chrome extension exploit:
    Attacker buys low-liquidity token at 300% over market to siphon victim balances into attacker sells.
    """
    res = threat_intel.evaluate_counter_trading_anomaly(
        symbol="SHITCOIN/USDT",
        trade_type="BUY",
        volume=10000.0,
        execution_price=4.50,            # Executing at $4.50
        reference_index_price=1.00,      # Fair market is $1.00 (+350% divergence)
        order_book_depth_usd=8000.0      # Very thin order book ($8,000 depth)
    )

    assert res.is_counter_trading_detected is True
    assert res.is_illiquid_market is True
    assert res.price_divergence_pct >= 300.0
    assert res.threat_score >= 0.85
    assert res.recommended_action == "HARD_BLOCK_QUARANTINE"
    assert any("SEVERE_PRICE_DIVERGENCE" in r for r in res.reasons)
    assert any("THIN_ORDER_BOOK_EXPLOITATION" in r for r in res.reasons)


def test_counter_trading_api_endpoint():
    """Tests the /api/v1/market/counter-trading-check endpoint logic."""
    from src.api.main import api_counter_trading_check, CounterTradingCheckRequest

    req = CounterTradingCheckRequest(
        symbol="MICRO/USDT",
        trade_type="BUY",
        volume=5000.0,
        execution_price=5.0,
        reference_index_price=2.0,
        order_book_depth_usd=12000.0
    )
    data = api_counter_trading_check(req)
    assert data["is_counter_trading_detected"] is True
    assert data["threat_score"] >= 0.80
    assert data["recommended_action"] == "HARD_BLOCK_QUARANTINE"


# =============================================================================
# 3. CRYPTOGRAPHIC TOKEN-DEVICE BINDING (ANTI-SESSION HIJACKING)
# =============================================================================

def test_token_device_binding_same_environment_validates():
    """Verifies that tokens used from the same client IP subnet and user-agent validate cleanly."""
    client_ip = "198.51.100.42"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"

    token = create_access_token(
        user_id=101,
        username="analyst_alice",
        role="analyst",
        client_ip=client_ip,
        user_agent=ua
    )

    payload = decode_jwt_token(token)
    assert "dph" in payload

    # Same client environment
    is_valid, reason = verify_token_device_binding(payload, current_ip=client_ip, current_ua=ua)
    assert is_valid is True
    assert reason is None

    # Legitimate mobile subnet hop (same /24 subnet)
    is_valid_subnet, _ = verify_token_device_binding(payload, current_ip="198.51.100.99", current_ua=ua)
    assert is_valid_subnet is True


def test_token_device_binding_stolen_cookie_different_ip_rejected():
    """
    Simulates token / cookie exfiltration by an infostealer or malicious extension:
    Token issued to analyst on corporate subnet is replayed from attacker's remote server.
    """
    victim_ip = "198.51.100.42"
    victim_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"

    token = create_access_token(
        user_id=202,
        username="manager_bob",
        role="fraud_manager",
        client_ip=victim_ip,
        user_agent=victim_ua
    )

    payload = decode_jwt_token(token)

    # Attacker relays token from completely different IP and headless bot
    attacker_ip = "203.0.113.88"
    attacker_ua = "Python-requests/2.31.0"

    is_valid, reason = verify_token_device_binding(
        payload,
        current_ip=attacker_ip,
        current_ua=attacker_ua
    )
    assert is_valid is False
    assert "SESSION_HIJACK_DETECTED" in reason


# =============================================================================
# 4. HYBRID RULE ENGINE INTEGRATION
# =============================================================================

def test_hybrid_rule_engine_evaluates_crypto_and_session_rules():
    """Verifies that the new dynamic risk rules trigger on poisoned addresses and siphoning."""
    engine = HybridRuleEngine()

    # Confirm default rules exist
    rules = engine.get_rules()
    rule_ids = {r["rule_id"] for r in rules}
    assert "RULE_ADDRESS_POISONING" in rule_ids
    assert "RULE_COUNTER_TRADING_SLIPPAGE" in rule_ids
    assert "RULE_SESSION_HIJACK_DRIFT" in rule_ids

    # Trigger Address Poisoning rule
    eval_poison = engine.evaluate(
        ml_score=0.10,
        amount=100.0,
        context_data={"address_poisoning_score": 0.95}
    )
    assert eval_poison.decision == ActionDecision.BLOCK
    assert any("RULE_ADDRESS_POISONING" in r for r in eval_poison.triggered_rules)

    # Trigger Counter-Trading Slippage rule
    eval_drain = engine.evaluate(
        ml_score=0.10,
        amount=100.0,
        context_data={"counter_trading_score": 0.88}
    )
    assert eval_drain.decision == ActionDecision.BLOCK
    assert any("RULE_COUNTER_TRADING_SLIPPAGE" in r for r in eval_drain.triggered_rules)

    # Trigger Session Hijack Drift rule
    eval_hijack = engine.evaluate(
        ml_score=0.10,
        amount=100.0,
        context_data={"session_hijack_score": 0.75}
    )
    assert eval_hijack.decision in (ActionDecision.CHALLENGE_2FA, ActionDecision.MANUAL_REVIEW, ActionDecision.BLOCK)
    assert any("RULE_SESSION_HIJACK_DRIFT" in r for r in eval_hijack.triggered_rules)
