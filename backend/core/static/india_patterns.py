"""
Garudatva v3 — India-specific fraud pattern signatures.
47 patterns covering UPI fraud, fake loans, Aadhaar harvesting,
banking trojans, and RAT infrastructure common in Indian cybercrime.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List

from models.ioc import IndiaPatternMatch
from utils.logger import get_logger

logger = get_logger(__name__)


# ── Pattern Definitions ──────────────────────────────────────────────────────

INDIA_PATTERNS = [
    # ── UPI Fraud (8 patterns) ───────────────────────────────────────────
    {
        "id": "IND_001", "name": "UPI VPA Harvest", "category": "UPI_FRAUD",
        "severity": "CRITICAL",
        "strings": ["upi://pay", "pa=", "pn=", "am=", "cu=INR"],
        "regex": r"upi://pay\?.*pa=[\w.@]+",
    },
    {
        "id": "IND_002", "name": "UPI Intent Intercept", "category": "UPI_FRAUD",
        "severity": "CRITICAL",
        "strings": ["android.intent.action.VIEW", "upi://", "UpiActivity"],
        "regex": None,
    },
    {
        "id": "IND_003", "name": "BHIM/GPay Package Spoof", "category": "UPI_FRAUD",
        "severity": "HIGH",
        "strings": ["com.google.android.apps.nbu.paisa.user",
                    "net.one97.paytm", "in.org.npci.upiapp"],
        "regex": None,
    },
    {
        "id": "IND_004", "name": "UPI PIN Keylogger", "category": "UPI_FRAUD",
        "severity": "CRITICAL",
        "strings": ["upiPin", "mpin", "setOnKeyListener", "KeyEvent.KEYCODE"],
        "regex": None,
    },
    {
        "id": "IND_005", "name": "UPI Collect Request Spoof", "category": "UPI_FRAUD",
        "severity": "HIGH",
        "strings": ["collectRequest", "payerVPA", "payeeVPA", "transactionRef"],
        "regex": None,
    },
    {
        "id": "IND_006", "name": "Fake UPI Success Screen", "category": "UPI_FRAUD",
        "severity": "HIGH",
        "strings": ["Payment Successful", "Transaction ID", "UTR"],
        "regex": r"UTR\s*:?\s*\d{12}",
    },
    {
        "id": "IND_007", "name": "NPCI API Abuse", "category": "UPI_FRAUD",
        "severity": "HIGH",
        "strings": ["upigateway.npci.org.in", "npci.org.in/upi"],
        "regex": None,
    },
    {
        "id": "IND_008", "name": "PhonePe/BHIM Overlay", "category": "UPI_FRAUD",
        "severity": "CRITICAL",
        "strings": ["com.phonepe.app", "TYPE_APPLICATION_OVERLAY",
                    "SYSTEM_ALERT_WINDOW"],
        "regex": None,
    },

    # ── Fake Loan App (7 patterns) ───────────────────────────────────────
    {
        "id": "IND_009", "name": "Contact Scraping", "category": "FAKE_LOAN",
        "severity": "HIGH",
        "strings": ["ContactsContract.Contacts", "getAllContacts",
                    "READ_CONTACTS", "uploadContacts"],
        "regex": None,
    },
    {
        "id": "IND_010", "name": "SMS OTP Harvest", "category": "FAKE_LOAN",
        "severity": "CRITICAL",
        "strings": ["SmsMessage.createFromPdu", "getMessageBody",
                    "RECEIVE_SMS", "otp", "OTP"],
        "regex": r"[Oo][Tt][Pp][\s:=]+\d{4,8}",
    },
    {
        "id": "IND_011", "name": "Photo Library Drain", "category": "FAKE_LOAN",
        "severity": "HIGH",
        "strings": ["MediaStore.Images", "READ_EXTERNAL_STORAGE",
                    "uploadImage", "bitmapToBase64"],
        "regex": None,
    },
    {
        "id": "IND_012", "name": "Loan Shark C2 Pattern", "category": "FAKE_LOAN",
        "severity": "HIGH",
        "strings": ["loanStatus", "dueDate", "penaltyRate", "collectionAgent"],
        "regex": r"(loan|emi|due).{0,30}(api|endpoint|server)",
    },
    {
        "id": "IND_013", "name": "RBI Fake Logo", "category": "FAKE_LOAN",
        "severity": "HIGH",
        "strings": ["Reserve Bank of India", "RBI Approved", "RBI Licensed"],
        "regex": r"RBI\s*(Approved|Licensed|Registered|Certified)",
    },
    {
        "id": "IND_014", "name": "Aadhaar KYC Phish", "category": "FAKE_LOAN",
        "severity": "CRITICAL",
        "strings": ["aadhaarNumber", "aadhaar_number", "Aadhaar Card",
                    "uploadAadhaar"],
        "regex": r"\b\d{4}[\s-]\d{4}[\s-]\d{4}\b",
    },
    {
        "id": "IND_015", "name": "PAN Harvesting", "category": "FAKE_LOAN",
        "severity": "HIGH",
        "strings": ["panNumber", "pan_card", "PAN Card", "uploadPAN"],
        "regex": r"[A-Z]{5}[0-9]{4}[A-Z]{1}",
    },

    # ── Aadhaar Harvesting (6 patterns) ──────────────────────────────────
    {
        "id": "IND_016", "name": "UIDAI API Abuse", "category": "AADHAAR",
        "severity": "CRITICAL",
        "strings": ["uidai.gov.in", "resident.uidai.gov.in",
                    "authserver.uidai.gov.in"],
        "regex": None,
    },
    {
        "id": "IND_017", "name": "Aadhaar QR Parse", "category": "AADHAAR",
        "severity": "HIGH",
        "strings": ["parseAadhaarQR", "AadhaarQRParser", "xmlAadhaar"],
        "regex": None,
    },
    {
        "id": "IND_018", "name": "Biometric Data Capture", "category": "AADHAAR",
        "severity": "CRITICAL",
        "strings": ["BiometricPrompt", "FingerprintManager",
                    "biometricData", "fingerprintTemplate"],
        "regex": None,
    },
    {
        "id": "IND_019", "name": "OTP-based Aadhaar Auth", "category": "AADHAAR",
        "severity": "HIGH",
        "strings": ["generateOTP", "verifyOTP", "aadhaarOTP", "mobileOTP"],
        "regex": None,
    },
    {
        "id": "IND_020", "name": "eKYC Data Exfil", "category": "AADHAAR",
        "severity": "CRITICAL",
        "strings": ["eKYC", "KycResponse", "kycData", "xmlBase64"],
        "regex": None,
    },
    {
        "id": "IND_021", "name": "DigiLocker Spoof", "category": "AADHAAR",
        "severity": "HIGH",
        "strings": ["digilocker.gov.in", "DigiLocker", "digitallocker"],
        "regex": None,
    },

    # ── Banking Trojans (8 patterns) ──────────────────────────────────────
    {
        "id": "IND_022", "name": "SBI/HDFC/ICICI Overlay", "category": "BANKING_TROJAN",
        "severity": "CRITICAL",
        "strings": ["com.sbi.SBIFreedomPlus", "com.snapwork.hdfc",
                    "com.csam.icici.bank.imobile"],
        "regex": None,
    },
    {
        "id": "IND_023", "name": "Net Banking Credential Steal", "category": "BANKING_TROJAN",
        "severity": "CRITICAL",
        "strings": ["netbanking", "customerID", "loginPassword",
                    "transactionPassword"],
        "regex": None,
    },
    {
        "id": "IND_024", "name": "IMPS/NEFT Transfer Initiation", "category": "BANKING_TROJAN",
        "severity": "CRITICAL",
        "strings": ["impsTransfer", "neftTransfer", "beneficiaryAccount",
                    "ifscCode"],
        "regex": r"[A-Z]{4}0[A-Z0-9]{6}",
    },
    {
        "id": "IND_025", "name": "mPIN Intercept", "category": "BANKING_TROJAN",
        "severity": "CRITICAL",
        "strings": ["mPIN", "setMPIN", "verifyMPIN", "changeMPIN"],
        "regex": None,
    },
    {
        "id": "IND_026", "name": "Debit Card Skimmer", "category": "BANKING_TROJAN",
        "severity": "CRITICAL",
        "strings": ["cardNumber", "cvv", "expiryDate", "cardPin",
                    "trackData"],
        "regex": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b",
    },
    {
        "id": "IND_027", "name": "Bank SMS Keyword Monitor", "category": "BANKING_TROJAN",
        "severity": "HIGH",
        "strings": ["debited", "credited", "account balance",
                    "SBI Alert", "HDFC Bank"],
        "regex": r"(debited|credited).{0,50}(Rs\.|INR|₹)\s*[\d,]+",
    },
    {
        "id": "IND_028", "name": "AnyDesk/TeamViewer RAT", "category": "BANKING_TROJAN",
        "severity": "CRITICAL",
        "strings": ["net.anydesk.app", "com.teamviewer.host",
                    "Accessibility Screen Sharing"],
        "regex": None,
    },
    {
        "id": "IND_029", "name": "VNC Screen Capture", "category": "BANKING_TROJAN",
        "severity": "CRITICAL",
        "strings": ["MediaProjection", "VirtualDisplay", "ImageReader",
                    "createVirtualDisplay"],
        "regex": None,
    },

    # ── RAT Infrastructure (6 patterns) ──────────────────────────────────
    {
        "id": "IND_030", "name": "Firebase C2 Polling", "category": "RAT",
        "severity": "HIGH",
        "strings": ["firebaseio.com", "getDatabase", "addValueEventListener",
                    "onDataChange"],
        "regex": r"https://[\w-]+\.firebaseio\.com",
    },
    {
        "id": "IND_031", "name": "Telegram Bot C2", "category": "RAT",
        "severity": "HIGH",
        "strings": ["api.telegram.org/bot", "sendMessage", "sendDocument",
                    "getUpdates"],
        "regex": r"api\.telegram\.org/bot[\w:]+/",
    },
    {
        "id": "IND_032", "name": "Reverse Shell Commands", "category": "RAT",
        "severity": "CRITICAL",
        "strings": ["Runtime.exec", "/bin/sh", "ProcessBuilder",
                    "cmd.exe", "/system/bin/sh"],
        "regex": None,
    },
    {
        "id": "IND_033", "name": "Keylogger Accessibility Service", "category": "RAT",
        "severity": "CRITICAL",
        "strings": ["AccessibilityService", "onAccessibilityEvent",
                    "TYPE_VIEW_TEXT_CHANGED", "getText"],
        "regex": None,
    },
    {
        "id": "IND_034", "name": "Location Tracker", "category": "RAT",
        "severity": "HIGH",
        "strings": ["FusedLocationProvider", "LocationManager",
                    "requestLocationUpdates", "uploadLocation"],
        "regex": None,
    },
    {
        "id": "IND_035", "name": "Camera Silent Capture", "category": "RAT",
        "severity": "CRITICAL",
        "strings": ["Camera2", "CameraManager", "CaptureRequest.CONTROL_AE_MODE",
                    "silentCapture"],
        "regex": None,
    },

    # ── WhatsApp/Social Fraud (5 patterns) ───────────────────────────────
    {
        "id": "IND_036", "name": "WhatsApp Message Intercept", "category": "SOCIAL_FRAUD",
        "severity": "HIGH",
        "strings": ["com.whatsapp", "WhatsApp", "com.whatsapp.w4b"],
        "regex": None,
    },
    {
        "id": "IND_037", "name": "Fake KBC/Lottery", "category": "SOCIAL_FRAUD",
        "severity": "MEDIUM",
        "strings": ["KBC", "Kaun Banega", "lottery winner", "prize money"],
        "regex": r"(won|winner|prize).{0,50}(lakh|crore|rupees|₹)",
    },
    {
        "id": "IND_038", "name": "ED/CBI Impersonation", "category": "SOCIAL_FRAUD",
        "severity": "HIGH",
        "strings": ["Enforcement Directorate", "Central Bureau",
                    "CBI Officer", "ED Notice"],
        "regex": None,
    },
    {
        "id": "IND_039", "name": "TRAI SIM Block Scam", "category": "SOCIAL_FRAUD",
        "severity": "MEDIUM",
        "strings": ["TRAI", "telecom regulatory", "SIM block",
                    "your number will be disconnected"],
        "regex": None,
    },
    {
        "id": "IND_040", "name": "Deepfake Video Call", "category": "SOCIAL_FRAUD",
        "severity": "HIGH",
        "strings": ["VideoCapture", "faceSwap", "deepfake", "rtmpStream"],
        "regex": None,
    },

    # ── Tax/Government Fraud (4 patterns) ────────────────────────────────
    {
        "id": "IND_041", "name": "ITR Refund Phish", "category": "GOV_FRAUD",
        "severity": "HIGH",
        "strings": ["incometaxindiaefiling.gov.in", "ITR", "income tax refund",
                    "TDS refund"],
        "regex": None,
    },
    {
        "id": "IND_042", "name": "GST Refund Scam", "category": "GOV_FRAUD",
        "severity": "HIGH",
        "strings": ["gst.gov.in", "GSTIN", "GST refund", "input tax credit"],
        "regex": r"\d{2}[A-Z]{5}\d{4}[A-Z]{1}[A-Z\d]{1}[Z]{1}[A-Z\d]{1}",
    },
    {
        "id": "IND_043", "name": "PM Yojana Fake", "category": "GOV_FRAUD",
        "severity": "MEDIUM",
        "strings": ["PM Kisan", "Pradhan Mantri", "Yojana", "government benefit",
                    "pm-kisan.gov.in"],
        "regex": None,
    },
    {
        "id": "IND_044", "name": "CoWIN Vaccine Phish", "category": "GOV_FRAUD",
        "severity": "MEDIUM",
        "strings": ["cowin.gov.in", "CoWIN", "vaccination certificate",
                    "Aarogya Setu"],
        "regex": None,
    },

    # ── Crypto Fraud (3 patterns) ─────────────────────────────────────────
    {
        "id": "IND_045", "name": "Crypto Wallet Drain", "category": "CRYPTO_FRAUD",
        "severity": "CRITICAL",
        "strings": ["mnemonic", "seedPhrase", "privateKey", "MetaMask",
                    "WalletConnect"],
        "regex": r"([a-z]+\s){11,23}[a-z]+",
    },
    {
        "id": "IND_046", "name": "Fake Trading App", "category": "CRYPTO_FRAUD",
        "severity": "HIGH",
        "strings": ["WazirX", "CoinDCX", "buyBitcoin", "tradingProfit",
                    "guaranteed returns"],
        "regex": None,
    },
    {
        "id": "IND_047", "name": "P2P Crypto Mule", "category": "CRYPTO_FRAUD",
        "severity": "HIGH",
        "strings": ["p2pTransfer", "cryptoMule", "usdt", "USDT transfer",
                    "tronLink"],
        "regex": r"T[A-Za-z1-9]{33}",
    },
]


class IndiaPatternsEngine:
    """
    Fast multi-pattern scanner for Indian cybercrime signatures.
    Runs on DEX strings, manifest content, and decoded resources.
    """

    def __init__(self):
        self.patterns = INDIA_PATTERNS
        self._compiled_regex = {
            p["id"]: re.compile(p["regex"], re.IGNORECASE)
            for p in self.patterns
            if p.get("regex")
        }
        logger.info(f"India patterns loaded: {len(self.patterns)} patterns")

    def scan(self, text_corpus: str) -> List[IndiaPatternMatch]:
        """
        Scan concatenated text content against all 47 patterns.
        text_corpus should be: manifest + DEX strings + resource strings joined.
        """
        matches: List[IndiaPatternMatch] = []

        for pattern in self.patterns:
            matched_strings: List[str] = []

            # String matching
            for needle in pattern["strings"]:
                if needle.lower() in text_corpus.lower():
                    matched_strings.append(needle)

            # Regex matching
            if pattern.get("regex") and pattern["id"] in self._compiled_regex:
                rx_matches = self._compiled_regex[pattern["id"]].findall(text_corpus)
                if rx_matches:
                    matched_strings.extend([str(m) for m in rx_matches[:5]])

            if matched_strings:
                matches.append(
                    IndiaPatternMatch(
                        pattern_id=pattern["id"],
                        pattern_name=pattern["name"],
                        category=pattern["category"],
                        matched_strings=list(set(matched_strings)),
                        severity=pattern["severity"],
                    )
                )

        if matches:
            logger.info(
                f"India patterns: {len(matches)} matches "
                f"({', '.join(m.pattern_id for m in matches[:5])}…)"
            )

        return matches

    def scan_strings_list(self, strings: List[str]) -> List[IndiaPatternMatch]:
        """Convenience wrapper for a list of extracted DEX strings."""
        return self.scan("\n".join(strings))
