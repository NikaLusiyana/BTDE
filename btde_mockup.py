import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
import random
import time
from datetime import datetime, timedelta
import plotly.graph_objects as go
import plotly.express as px
from collections import defaultdict
import re
import sqlite3
import pickle
from pathlib import Path
import os
import requests

# =============================================================================
# KONFIGURASI APLIKASI
# =============================================================================

st.set_page_config(
    page_title="BTDE - Behavioral Threat Detection Engine",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =============================================================================
# CLASS: TRAFFIC GENERATOR (Dari v3, Ditingkatkan)
# =============================================================================

class TrafficGenerator:
    """Generator untuk traffic normal dan simulasi berbagai jenis serangan"""
    
    def __init__(self):
        self.normal_ips = ['192.168.1.100', '192.168.1.101', '192.168.1.102', '10.0.0.50', '10.0.0.51']
        self.attacker_ips = ['203.0.113.15', '198.51.100.23', '192.0.2.45', '185.220.101.50']
        self.normal_users = ['user_alice', 'user_bob', 'user_charlie', 'user_diana', 'user_eve']
        self.normal_endpoints = [
            '/dashboard', '/profile', '/products', '/checkout', '/api/data',
            '/account/settings', '/product/list', '/about'
        ]
        self.high_risk_countries = ['Nigeria', 'China', 'Russia', 'Vietnam']
        self.normal_locations = ['Jakarta', 'Surabaya', 'Medan', 'Bandung']
        
    def generate_normal_log(self):
        """Generate log traffic normal"""
        user_id = random.choice(self.normal_users)
        
        return {
            'timestamp': datetime.now(),
            'ip_address': random.choice(self.normal_ips),
            'user_id': user_id,
            'request_uri': random.choice(self.normal_endpoints),
            'request_parameters': '',
            'request_method': random.choice(['GET', 'POST']),
            'status_code': random.choice([200, 200, 200, 304]),
            'user_agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
            'response_time': random.uniform(0.1, 2.0),
            'transaction_value': random.uniform(50000, 1000000),
            'transaction_count_1h': random.randint(0, 3),
            'failed_login_count_1h': 0,
            'unique_usernames_tried': 1,
            'small_transactions_count': 0,
            'multiple_cards_used': False,
            'login_location': random.choice(self.normal_locations),
            'device_id': f"device_{random.randint(100, 999)}",
            'user_role': 'user',
            'billing_country': 'Indonesia',
            'shipping_country': 'Indonesia',
            'card_transaction_count_1h': random.randint(0, 2),
            'uploaded_file_extension': '.jpg',
            'file_content_contains_code': False,
            'data_export_size': 0,
            'database_query_returns': 0,
            'database_access_time': datetime.now().hour,
            'accessed_sensitive_tables': False,
            'password_changed_immediately': False,
            'account_age_days': random.randint(30, 500),
            'type': 'normal',
            'simulated_attack_type': 'Normal'
        }
    
    def generate_attack_log(self, attack_type):
        """Generate log untuk berbagai jenis serangan sesuai 14 rules"""
        base_log = self.generate_normal_log()
        base_log['ip_address'] = random.choice(self.attacker_ips)
        base_log['type'] = attack_type
        base_log['simulated_attack_type'] = attack_type
        
        current_time = datetime.now()
        
        # Web Application Attacks
        if attack_type == 'SQLi':
            base_log['request_uri'] = "/product/view"
            base_log['request_parameters'] = random.choice([
                "id=123' OR 1=1 --",
                "id=1 UNION SELECT * FROM users",
                "id=1'; DROP TABLE users--"
            ])
            base_log['status_code'] = random.choice([401, 403, 500])
            
        elif attack_type == 'XSS':
            base_log['request_uri'] = "/search"
            base_log['request_parameters'] = random.choice([
                "query=<script>alert(1)</script>",
                "query=<img src=x onerror=alert(1)>",
                "query=javascript:alert('XSS')"
            ])
            
        elif attack_type == 'PathTraversal':
            base_log['request_uri'] = random.choice([
                "/download?file=../../../etc/passwd",
                "/files/../../Windows/System32",
                "/api/file?path=..\\..\\sensitive.txt"
            ])
            
        elif attack_type == 'MaliciousUpload':
            base_log['request_uri'] = "/upload"
            base_log['uploaded_file_extension'] = random.choice(['.php', '.exe', '.sh', '.bat'])
            base_log['file_content_contains_code'] = True
            
        # Authentication Attacks
        elif attack_type == 'BruteForce':
            base_log['request_uri'] = "/login"
            base_log['failed_login_count_1h'] = random.randint(15, 50)
            base_log['status_code'] = 401
            base_log['user_agent'] = 'python-requests/2.28.0'
            
        elif attack_type == 'CredentialStuffing':
            base_log['request_uri'] = "/login"
            base_log['failed_login_count_1h'] = random.randint(6, 12)
            base_log['unique_usernames_tried'] = random.randint(15, 50)
            base_log['status_code'] = 401
            
        elif attack_type == 'ImpossibleTravel':
            base_log['request_uri'] = "/login"
            base_log['login_location'] = 'New York'
            # Simulasi login sebelumnya di Jakarta 30 menit lalu
            if base_log['user_id'] in st.session_state.user_context:
                st.session_state.user_context[base_log['user_id']]['last_login_location'] = 'Jakarta'
                st.session_state.user_context[base_log['user_id']]['last_login_time'] = current_time - timedelta(minutes=30)
            
        elif attack_type == 'AccountTakeover':
            base_log['request_uri'] = "/account/settings"
            base_log['device_id'] = f"new_suspicious_device_{random.randint(1, 99)}"
            base_log['login_location'] = random.choice(self.high_risk_countries)
            base_log['password_changed_immediately'] = True
            
        # Transaction Fraud
        elif attack_type == 'CardTesting':
            base_log['request_uri'] = "/payment/submit"
            base_log['transaction_count_1h'] = random.randint(8, 15)
            base_log['transaction_value'] = random.uniform(1000, 5000)
            base_log['small_transactions_count'] = base_log['transaction_count_1h']
            base_log['multiple_cards_used'] = True
            
        elif attack_type == 'HighValueFraud':
            base_log['request_uri'] = "/checkout/complete"
            base_log['transaction_value'] = random.uniform(5000000, 15000000)
            base_log['account_age_days'] = random.randint(1, 5)
            
        elif attack_type == 'GeographicMismatch':
            base_log['request_uri'] = "/checkout/complete"
            base_log['billing_country'] = 'Indonesia'
            base_log['shipping_country'] = random.choice(self.high_risk_countries)
            
        elif attack_type == 'VelocityCheck':
            base_log['request_uri'] = "/payment/submit"
            base_log['transaction_count_1h'] = random.randint(12, 25)
            base_log['card_transaction_count_1h'] = random.randint(6, 15)
            
        # Data Exfiltration
        elif attack_type == 'BulkDownload':
            base_log['request_uri'] = "/api/data/export"
            base_log['data_export_size'] = random.uniform(15, 50)
            base_log['database_query_returns'] = random.randint(15000, 50000)
            base_log['user_role'] = 'user'
            
        elif attack_type == 'OffHoursAccess':
            base_log['request_uri'] = "/api/db/query"
            base_log['database_access_time'] = random.choice([23, 0, 1, 2, 3, 4])
            base_log['accessed_sensitive_tables'] = True
            base_log['user_role'] = 'user'
        
        return base_log

# =============================================================================
# CLASS: BTDE ENGINE (Gabungan Rule-Based + ML dari kedua versi)
# =============================================================================

class BTDEEngine:
    """Engine utama untuk deteksi ancaman dengan 14 rules + ML"""
    
    def __init__(self):
        # Pattern untuk deteksi berbasis rule
        self.sql_patterns = [
            r"(\bOR\b\s+['\"]?1['\"]?\s*=\s*['\"]?1)",
            r"(\bUNION\b\s+\bSELECT\b)",
            r"(\bDROP\b\s+\bTABLE\b)",
            r"(--\s*$)",
            r"(;\s*\bSELECT\b)",
            r"(\bEXEC\b\s*\()",
        ]
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onclick\s*=",
            r"<iframe",
        ]
        self.path_traversal_patterns = [
            r"\.\./",
            r"\.\.\\",
            r"/etc/passwd",
            r"/etc/shadow",
            r"C:\\Windows",
        ]
        self.malicious_extensions = ['.php', '.exe', '.sh', '.bat', '.cmd']
        self.high_risk_countries = ['Nigeria', 'China', 'Russia', 'Vietnam']
        
        # ML Model
        self.anomaly_model = None
        self.baseline_data = []
        
    def rule_based_detection(self, log_entry):
        """Implementasi 14 Rule-Based Detection (A1-A4, W1-W4, T1-T4, D1-D2)"""
        score = 0
        alerts = []
        actions = []
        detections = []
        
        uri = log_entry.get('request_uri', '')
        params = log_entry.get('request_parameters', '')
        
        # === CATEGORY 1: AUTHENTICATION ANOMALIES ===
        
        # Rule A1: Brute Force Detection
        if log_entry.get('failed_login_count_1h', 0) > 10:
            score += 60
            alerts.append(f"A1: Brute Force ({log_entry['failed_login_count_1h']} failed logins)")
            actions.append("BLOCK_IP_1H")
            detections.append({
                'type': 'Brute Force Attack',
                'rule': 'A1',
                'confidence': 92,
                'score': 60
            })
        
        # Rule A2: Credential Stuffing
        if (log_entry.get('failed_login_count_1h', 0) > 5 and 
            log_entry.get('unique_usernames_tried', 0) > 10):
            score += 70
            alerts.append("A2: Credential Stuffing Detected")
            actions.append("BLOCK_IP_24H")
            detections.append({
                'type': 'Credential Stuffing',
                'rule': 'A2',
                'confidence': 95,
                'score': 70
            })
        
        # Rule A3: Impossible Travel
        user_id = log_entry.get('user_id')
        if user_id in st.session_state.user_context:
            user_ctx = st.session_state.user_context[user_id]
            prev_location = user_ctx.get('last_login_location')
            prev_time = user_ctx.get('last_login_time')
            current_location = log_entry.get('login_location')
            
            if prev_location and prev_time and current_location != prev_location:
                time_diff = (datetime.now() - prev_time).total_seconds()
                if time_diff < 7200:  # Kurang dari 2 jam
                    score += 80
                    alerts.append(f"A3: Impossible Travel ({prev_location} -> {current_location} in {time_diff/60:.0f}min)")
                    actions.append("CHALLENGE_2FA")
                    detections.append({
                        'type': 'Impossible Travel',
                        'rule': 'A3',
                        'confidence': 88,
                        'score': 80
                    })
        
        # Rule A4: Account Takeover Pattern
        if user_id in st.session_state.user_context:
            user_ctx = st.session_state.user_context[user_id]
            if (log_entry.get('device_id') != user_ctx.get('last_device') and
                log_entry.get('login_location') != user_ctx.get('last_login_location') and
                log_entry.get('password_changed_immediately', False)):
                score += 90
                alerts.append("A4: Potential Account Takeover")
                actions.append("LOCK_ACCOUNT + NOTIFY_USER")
                detections.append({
                    'type': 'Account Takeover',
                    'rule': 'A4',
                    'confidence': 90,
                    'score': 90
                })
        
        # === CATEGORY 2: WEB APPLICATION ATTACKS ===
        
        # Rule W1: SQL Injection
        for pattern in self.sql_patterns:
            if re.search(pattern, uri + params, re.IGNORECASE):
                score += 100
                alerts.append("W1: SQL Injection Attempt Detected")
                actions.append("BLOCK_REQUEST + LOG_FULL_REQUEST")
                detections.append({
                    'type': 'SQL Injection',
                    'rule': 'W1',
                    'confidence': 95,
                    'score': 100
                })
                break
        
        # Rule W2: XSS Attempt
        for pattern in self.xss_patterns:
            if re.search(pattern, params, re.IGNORECASE):
                score += 90
                alerts.append("W2: XSS Attempt Detected")
                actions.append("BLOCK_REQUEST + SANITIZE")
                detections.append({
                    'type': 'Cross-Site Scripting (XSS)',
                    'rule': 'W2',
                    'confidence': 90,
                    'score': 90
                })
                break
        
        # Rule W3: Path Traversal
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, uri):
                score += 100
                alerts.append("W3: Path Traversal Attempt")
                actions.append("BLOCK_REQUEST")
                detections.append({
                    'type': 'Path Traversal',
                    'rule': 'W3',
                    'confidence': 88,
                    'score': 100
                })
                break
        
        # Rule W4: Malicious File Upload
        if (log_entry.get('uploaded_file_extension') in self.malicious_extensions or
            log_entry.get('file_content_contains_code', False)):
            score += 95
            alerts.append(f"W4: Malicious File Upload ({log_entry.get('uploaded_file_extension')})")
            actions.append("BLOCK_UPLOAD + QUARANTINE")
            detections.append({
                'type': 'Malicious File Upload',
                'rule': 'W4',
                'confidence': 93,
                'score': 95
            })
        
        # === CATEGORY 3: TRANSACTION FRAUD ===
        
        # Rule T1: Card Testing
        if (log_entry.get('transaction_count_1h', 0) > 5 and
            log_entry.get('small_transactions_count', 0) == log_entry.get('transaction_count_1h', 0) and
            log_entry.get('multiple_cards_used', False)):
            score += 85
            alerts.append("T1: Card Testing Detected")
            actions.append("BLOCK_IP + DECLINE_TRANSACTIONS")
            detections.append({
                'type': 'Card Testing',
                'rule': 'T1',
                'confidence': 87,
                'score': 85
            })
        
        # Rule T2: High-Value Fraud
        user_avg = log_entry.get('user_avg_transaction', 500000)
        if (log_entry.get('transaction_value', 0) > (user_avg * 5) and
            log_entry.get('account_age_days', 365) < 7):
            score += 70
            alerts.append(f"T2: High-Value Fraud (Rp {log_entry['transaction_value']:,.0f})")
            actions.append("MANUAL_REVIEW")
            detections.append({
                'type': 'High-Value Fraud',
                'rule': 'T2',
                'confidence': 75,
                'score': 70
            })
        
        # Rule T3: Geographic Mismatch
        if (log_entry.get('billing_country') != log_entry.get('shipping_country') and
            log_entry.get('shipping_country') in self.high_risk_countries):
            score += 50
            alerts.append(f"T3: Geo Mismatch ({log_entry['billing_country']}->{log_entry['shipping_country']})")
            actions.append("MANUAL_REVIEW")
            detections.append({
                'type': 'Geographic Mismatch',
                'rule': 'T3',
                'confidence': 70,
                'score': 50
            })
        
        # Rule T4: Velocity Check
        if (log_entry.get('transaction_count_1h', 0) > 10 or 
            log_entry.get('card_transaction_count_1h', 0) > 5):
            score += 65
            alerts.append("T4: Transaction Velocity Exceeded")
            actions.append("RATE_LIMIT")
            detections.append({
                'type': 'Velocity Abuse',
                'rule': 'T4',
                'confidence': 80,
                'score': 65
            })
        
        # === CATEGORY 4: DATA EXFILTRATION ===
        
        # Rule D1: Bulk Data Download
        if ((log_entry.get('data_export_size', 0) > 10 or 
             log_entry.get('database_query_returns', 0) > 10000) and
            log_entry.get('user_role') != 'admin'):
            score += 95
            alerts.append("D1: Potential Data Exfiltration")
            actions.append("BLOCK + ALERT_ADMIN")
            detections.append({
                'type': 'Bulk Data Exfiltration',
                'rule': 'D1',
                'confidence': 85,
                'score': 95
            })
        
        # Rule D2: Off-Hours Access
        current_hour = log_entry.get('database_access_time', datetime.now().hour)
        if ((current_hour >= 22 or current_hour < 6) and
            log_entry.get('user_role') != 'admin' and
            log_entry.get('accessed_sensitive_tables', False)):
            score += 60
            alerts.append(f"D2: Unusual Off-Hours Access ({current_hour}:00)")
            actions.append("CHALLENGE_MFA + LOG")
            detections.append({
                'type': 'Off-Hours Access',
                'rule': 'D2',
                'confidence': 75,
                'score': 60
            })
        
        return {
            'detected': len(detections) > 0,
            'detections': detections,
            'rule_score': score,
            'alerts': alerts,
            'actions': actions
        }
    
    def train_anomaly_model(self, baseline_logs):
        """Training ML model dengan baseline data"""
        if len(baseline_logs) < 10:
            return False
        
        features = []
        for log in baseline_logs:
            features.append([
                log.get('response_time', 0),
                log.get('transaction_value', 0),
                log.get('status_code', 200),
                len(log.get('request_uri', '')),
                log.get('transaction_count_1h', 0)
            ])
        
        X = np.array(features)
        self.anomaly_model = IsolationForest(contamination=0.05, random_state=42)
        self.anomaly_model.fit(X)
        self.baseline_data = baseline_logs
        return True
    
    def anomaly_detection(self, log_entry):
        """Deteksi anomali menggunakan ML"""
        if self.anomaly_model is None:
            return {
                'is_anomaly': False,
                'anomaly_score': 0,
                'alerts': []
            }
        
        feature = np.array([[
            log_entry.get('response_time', 0),
            log_entry.get('transaction_value', 0),
            log_entry.get('status_code', 200),
            len(log_entry.get('request_uri', '')),
            log_entry.get('transaction_count_1h', 0)
        ]])
        
        prediction = self.anomaly_model.predict(feature)
        anomaly_score_raw = self.anomaly_model.score_samples(feature)[0]
        
        is_anomaly = prediction[0] == -1
        anomaly_score = 0
        alerts = []
        
        if is_anomaly:
            baseline_avg = np.mean([log.get('transaction_value', 0) for log in self.baseline_data])
            if log_entry.get('transaction_value', 0) > baseline_avg * 3:
                anomaly_score = 70
                alerts.append(f"ML Anomaly: Transaction Value Outlier (Rp {log_entry['transaction_value']:,.0f})")
            else:
                anomaly_score = 40
                alerts.append("ML Anomaly: Behavioral Pattern Deviation")
        
        return {
            'is_anomaly': is_anomaly,
            'anomaly_score': anomaly_score,
            'raw_score': anomaly_score_raw,
            'alerts': alerts
        }

    # ------------------ Feature extraction & behavioral helpers ------------------
    def extract_behavioral_features(self, log_entry):
        """Extract comprehensive behavioral features (user/ip/transaction-level)."""
        features = {
            'failed_login_count_1h': self._count_failed_logins(log_entry.get('user_id')),
            'successful_login_count_24h': self._count_successful_logins(log_entry.get('user_id')),
            'unique_ips_7d': self._count_unique_ips(log_entry.get('user_id')),
            'avg_session_duration': self._get_avg_session(log_entry.get('user_id')),

            'request_count_1h': self._count_ip_requests(log_entry.get('ip_address')),
            'unique_users_24h': self._count_ip_users(log_entry.get('ip_address')),
            'failed_login_ratio': self._calculate_failed_ratio(log_entry.get('ip_address')),

            'transaction_velocity': self._get_transaction_velocity(log_entry.get('user_id')),
            'billing_shipping_mismatch': log_entry.get('billing_country') != log_entry.get('shipping_country'),
            'new_device': self._is_new_device(log_entry.get('user_id'), log_entry.get('device_id')),
            'unusual_time': self._is_unusual_login_time(log_entry.get('user_id'), log_entry.get('timestamp'))
        }
        return features

    def _recent_logs(self, minutes=60):
        now = datetime.now()
        return [l for l in st.session_state.logs if isinstance(l.get('timestamp'), datetime) and (now - l.get('timestamp')).total_seconds() <= minutes*60]

    def _count_failed_logins(self, user_id):
        if not user_id:
            return 0
        now = datetime.now()
        cnt = 0
        for l in st.session_state.logs:
            if l.get('user_id') == user_id and isinstance(l.get('timestamp'), datetime):
                if (now - l.get('timestamp')).total_seconds() <= 3600:
                    cnt += int(l.get('failed_login_count_1h', 0))
        return cnt

    def _count_successful_logins(self, user_id):
        if not user_id:
            return 0
        now = datetime.now()
        cnt = 0
        for l in st.session_state.logs:
            if l.get('user_id') == user_id and 'login' in str(l.get('request_uri','')).lower() and l.get('status_code') == 200:
                if (now - l.get('timestamp')).total_seconds() <= 24*3600:
                    cnt += 1
        return cnt

    def _count_unique_ips(self, user_id, days=7):
        if not user_id:
            return 0
        now = datetime.now()
        ips = set()
        for l in st.session_state.logs:
            if l.get('user_id') == user_id and isinstance(l.get('timestamp'), datetime):
                if (now - l.get('timestamp')).days <= days:
                    ips.add(l.get('ip_address'))
        return len(ips)

    def _get_transaction_velocity(self, user_id):
        now = datetime.now()
        return sum(int(l.get('transaction_count_1h', 0)) for l in st.session_state.logs if l.get('user_id') == user_id and isinstance(l.get('timestamp'), datetime) and (now - l.get('timestamp')).total_seconds() <= 3600)

    def _is_new_device(self, user_id, device_id):
        if user_id in st.session_state.user_context:
            return device_id != st.session_state.user_context[user_id].get('last_device')
        return True

    def _is_unusual_login_time(self, user_id, ts):
        try:
            if user_id in st.session_state.user_context and isinstance(ts, datetime):
                normal_hours = st.session_state.user_context[user_id].get('normal_hours', (6,22))
                return not (normal_hours[0] <= ts.hour <= normal_hours[1])
        except Exception:
            pass
        return False

    def get_user_history(self, user_id, metric_type='transaction_value', limit=100):
        vals = [l.get(metric_type, 0) for l in st.session_state.logs if l.get('user_id') == user_id]
        return vals[-limit:]

    def get_historical_traffic(self, hour):
        # returns list of counts per day for given hour
        counts = []
        by_day = defaultdict(int)
        for l in st.session_state.logs:
            if isinstance(l.get('timestamp'), datetime):
                key = l['timestamp'].date()
                if l['timestamp'].hour == hour:
                    by_day[key] += 1
        for k in sorted(by_day.keys()):
            counts.append(by_day[k])
        return counts

    # ------------------ Statistical / ML enhancements ------------------
    def z_score_analysis(self, user_id, current_value, metric_type='transaction_value'):
        """Z-Score analysis untuk transaction anomaly"""
        user_history = self.get_user_history(user_id, metric_type)
        if len(user_history) < 10:
            return 0
        mean_val = np.mean(user_history)
        std_val = np.std(user_history)
        if std_val == 0:
            return 0
        z_score = abs((current_value - mean_val) / std_val)
        if z_score > 3:
            return min(z_score * 20, 100)
        elif z_score > 2:
            return z_score * 10
        return 0

    def time_series_analysis(self, current_traffic):
        """Traffic pattern anomaly detection using z-score against historical per-hour counts"""
        hour = datetime.now().hour
        historical_traffic = self.get_historical_traffic(hour)
        if not historical_traffic:
            return 0
        avg_traffic = np.mean(historical_traffic)
        std_traffic = np.std(historical_traffic)
        if std_traffic == 0:
            return 0
        z_score = (current_traffic - avg_traffic) / std_traffic
        if abs(z_score) > 3:
            return min(abs(z_score) * 15, 80)
        return 0

    # ------------------ Tiered / optimized analysis ------------------
    def apply_fast_rules(self, log_entry):
        """Fast rules that run first for quick triage"""
        fast_score = 0
        # Immediate block for known blocked IP
        if log_entry.get('ip_address') in st.session_state.blocked_ips:
            return 100
        # Simple pattern checks
        params = str(log_entry.get('request_parameters', '')).lower()
        uri = str(log_entry.get('request_uri', '')).lower()
        if any(p in params or p in uri for p in ["' or", "<script>", "../", "drop table"]):
            fast_score += 80
        return fast_score

    def apply_statistical_checks(self, log_entry):
        """Apply lightweight statistical checks using behavioral features"""
        score = 0
        features = self.extract_behavioral_features(log_entry)
        # Use z-score on transaction value
        val = log_entry.get('transaction_value', 0)
        score += self.z_score_analysis(log_entry.get('user_id'), val)
        # time-series traffic anomaly
        current_traffic = self._count_ip_requests(log_entry.get('ip_address'))
        score += self.time_series_analysis(current_traffic)
        return score

    def analyze_request_optimized(self, log_entry):
        """Tiered analysis for performance: fast -> statistical -> ML"""
        risk_score = self.apply_fast_rules(log_entry)
        if risk_score >= 100:
            return risk_score
        if risk_score < st.session_state.get('alert_threshold', 40):
            # perform statistical checks only if above low fast_score
            stat = self.apply_statistical_checks(log_entry)
            risk_score += stat
            if risk_score < st.session_state.get('alert_threshold', 60):
                return risk_score
        # else use full ML anomaly detection
        anomaly_res = self.anomaly_detection(log_entry)
        anomaly_score = anomaly_res.get('anomaly_score', 0) if isinstance(anomaly_res, dict) else anomaly_res
        risk_score += anomaly_score
        return risk_score
    
    def calculate_risk_score(self, rule_score, anomaly_score, log_entry):
        """Kalkulasi risk score dengan context multiplier"""
        context_multiplier = 1.0
        # Apply user-configured weights if available in session_state
        try:
            rule_w = float(st.session_state.get('rule_weight', 1.0))
            anomaly_w = float(st.session_state.get('anomaly_weight', 1.0))
        except Exception:
            rule_w = 1.0
            anomaly_w = 1.0
        
        # Context berdasarkan endpoint sensitif
        sensitive_paths = ['/admin', '/payment', '/checkout', '/api/db', '/account']
        if any(path in log_entry.get('request_uri', '') for path in sensitive_paths):
            context_multiplier = 1.2
        
        # Context berdasarkan IP mencurigakan
        if log_entry.get('ip_address', '').startswith(('203.', '198.', '185.')):
            context_multiplier *= 1.1
        
        total_score = (rule_score * rule_w + anomaly_score * anomaly_w) * context_multiplier
        final_score = min(total_score, 100)
        
        # Penentuan risk level
        if final_score >= 80:
            level = 'Critical'
            color = '#dc2626'
            emoji = '🔴'
        elif final_score >= 60:
            level = 'High'
            color = '#f59e0b'
            emoji = '🟠'
        elif final_score >= 40:
            level = 'Medium'
            color = '#eab308'
            emoji = '🟡'
        else:
            level = 'Low'
            color = '#22c55e'
            emoji = '🟢'
        
        return {
            'score': round(final_score, 2),
            'level': level,
            'color': color,
            'emoji': emoji
        }
    
    def analyze_log(self, log_entry):
        """Analisis komprehensif untuk satu log entry"""
        # Fast-path: apply quick rules first
        fast_score = self.apply_fast_rules(log_entry)
        if fast_score >= 100:
            # immediate critical
            rule_result = {
                'detected': True,
                'detections': [{'type': 'Fast Rule Match', 'rule': 'FAST', 'confidence': 99, 'score': fast_score}],
                'rule_score': fast_score,
                'alerts': ['FAST_RULE_TRIGGERED'],
                'actions': ['BLOCK_IP']
            }
            anomaly_result = {'is_anomaly': False, 'anomaly_score': 0, 'alerts': []}
            risk = self.calculate_risk_score(rule_result['rule_score'], 0, log_entry)
            return {
                'log': log_entry,
                'rule_detection': rule_result,
                'anomaly_detection': anomaly_result,
                'risk': risk
            }

        # Normal analysis
        rule_result = self.rule_based_detection(log_entry)
        anomaly_result = self.anomaly_detection(log_entry)

        # incorporate fast_score into rule score (lightweight escalation)
        if fast_score > 0:
            rule_result['rule_score'] = rule_result.get('rule_score', 0) + fast_score
            rule_result.setdefault('alerts', []).append('FAST_RULE_PARTIAL')
            rule_result.setdefault('actions', [])

        risk = self.calculate_risk_score(
            rule_result['rule_score'],
            anomaly_result['anomaly_score'],
            log_entry
        )
        
        # Update user context jika login berhasil
        if ('login' in log_entry.get('request_uri', '') and 
            log_entry.get('user_id') != 'guest' and 
            risk['score'] < 60):
            user_id = log_entry['user_id']
            if user_id in st.session_state.user_context:
                st.session_state.user_context[user_id]['last_login_time'] = datetime.now()
                st.session_state.user_context[user_id]['last_login_location'] = log_entry.get('login_location')
                st.session_state.user_context[user_id]['last_device'] = log_entry.get('device_id')
        
        return {
            'log': log_entry,
            'rule_detection': rule_result,
            'anomaly_detection': anomaly_result,
            'risk': risk
        }

# =============================================================================
# INISIALISASI SESSION STATE
# =============================================================================

def init_session_state():
    """Inisialisasi semua state yang dibutuhkan"""
    if 'logs' not in st.session_state:
        st.session_state.logs = []
    
    if 'alerts' not in st.session_state:
        st.session_state.alerts = []
    
    if 'blocked_ips' not in st.session_state:
        st.session_state.blocked_ips = set()
    
    if 'btde_engine' not in st.session_state:
        st.session_state.btde_engine = BTDEEngine()
    
    if 'traffic_gen' not in st.session_state:
        st.session_state.traffic_gen = TrafficGenerator()
    
    if 'is_trained' not in st.session_state:
        st.session_state.is_trained = False
    
    if 'stats' not in st.session_state:
        st.session_state.stats = {
            'total_requests': 0,
            'threats_detected': 0,
            'blocked_requests': 0,
            'normal_traffic': 0,
            'attack_traffic': 0,
            # action tracking
            'actions_executed': 0,
            'significant_actions': 0
        }
    
    if 'user_context' not in st.session_state:
        st.session_state.user_context = {
            f"user_{name}": {
                "last_login_time": datetime.now() - timedelta(hours=random.randint(3, 100)),
                "last_login_location": random.choice(["Jakarta", "Surabaya", "Medan"]),
                "last_device": f"device_{random.randint(100, 999)}",
                "avg_transaction": random.uniform(200000, 700000),
                "account_age_days": random.randint(10, 500),
                "password_changed_recently": False,
                "user_role": random.choice(['user', 'user', 'user', 'admin']),
                "normal_hours": (6, 22)
            } for name in ['alice', 'bob', 'charlie', 'diana', 'eve']
        }
    
    if 'running' not in st.session_state:
        st.session_state.running = False
    # Scoring and persistence defaults
    if 'rule_weight' not in st.session_state:
        st.session_state.rule_weight = 1.0
    if 'anomaly_weight' not in st.session_state:
        st.session_state.anomaly_weight = 1.0
    if 'alert_threshold' not in st.session_state:
        st.session_state.alert_threshold = 40
    if 'autosave_sqlite' not in st.session_state:
        st.session_state.autosave_sqlite = False
    if 'model_path' not in st.session_state:
        st.session_state.model_path = 'btde_anomaly_model.pkl'
    
    # Automated Response Engine
    if 'auto_response_engine' not in st.session_state:
        st.session_state.auto_response_engine = AutomatedResponseEngine()
    if 'response_actions' not in st.session_state:
        st.session_state.response_actions = []
    if 'locked_accounts' not in st.session_state:
        st.session_state.locked_accounts = {}
    if 'rate_limits' not in st.session_state:
        st.session_state.rate_limits = {}
    if 'monitored_entities' not in st.session_state:
        st.session_state.monitored_entities = set()
    if 'review_queue' not in st.session_state:
        st.session_state.review_queue = []
    if 'daily_digest_queue' not in st.session_state:
        st.session_state.daily_digest_queue = []

    # Community sharing defaults
    if 'community_enabled' not in st.session_state:
        st.session_state.community_enabled = False
    if 'community_hub_url' not in st.session_state:
        st.session_state.community_hub_url = 'http://localhost:8080'
    if 'community_api_key' not in st.session_state:
        st.session_state.community_api_key = ''
    if 'community_client' not in st.session_state:
        st.session_state.community_client = None

    # Try to load existing model if present
    try:
        model_file = Path(st.session_state.model_path)
        if model_file.exists() and st.session_state.btde_engine.anomaly_model is None:
            with open(model_file, 'rb') as f:
                st.session_state.btde_engine.anomaly_model = pickle.load(f)
                st.session_state.is_trained = True
    except Exception:
        # ignore load errors
        pass


def _get_db_path() -> Path:
    return Path.cwd() / 'btde_logs.db'


def _ensure_db(conn: sqlite3.Connection):
    conn.execute('''
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        ip_address TEXT,
        user_id TEXT,
        request_uri TEXT,
        request_parameters TEXT,
        total_score REAL,
        risk_level TEXT,
        alerts TEXT,
        actions TEXT,
        is_attack INTEGER,
        simulated_attack_type TEXT
    )
    ''')
    conn.commit()


def save_log_to_sqlite(log: dict):
    db = _get_db_path()
    conn = sqlite3.connect(str(db))
    try:
        _ensure_db(conn)
        conn.execute(
            '''INSERT INTO logs (timestamp, ip_address, user_id, request_uri, request_parameters, total_score, risk_level, alerts, actions, is_attack, simulated_attack_type)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (
                str(log.get('timestamp')),
                log.get('ip_address'),
                log.get('user_id'),
                log.get('request_uri'),
                str(log.get('request_parameters', '')),
                float(log.get('total_score', 0)),
                str(log.get('risk_level', '')),
                str(log.get('alerts', '')),
                str(log.get('actions', '')),
                1 if log.get('type') != 'normal' else 0,
                str(log.get('simulated_attack_type', ''))
            )
        )
        conn.commit()
    finally:
        conn.close()


def save_model(anomaly_model, path: str):
    try:
        with open(path, 'wb') as f:
            pickle.dump(anomaly_model, f)
        return True
    except Exception:
        return False


# =============================================================================
# CLASS: AUTOMATED RESPONSE ENGINE
# =============================================================================

class AutomatedResponseEngine:
    """Automated response actions based on risk score and confidence level."""
    
    # Response Actions Matrix
    RESPONSE_MATRIX = {
        (81, 100, 'HIGH'): ['AUTO_BLOCK', 'LOCK_ACCOUNT', 'EMAIL_USER', 'ALERT_ADMIN'],
        (81, 100, 'MEDIUM'): ['CHALLENGE_MFA', 'ALERT_ADMIN', 'MONITOR_CLOSELY'],
        (61, 80, 'HIGH'): ['RATE_LIMIT', 'REAL_TIME_ALERT', 'REVIEW_QUEUE'],
        (61, 80, 'MEDIUM'): ['CAPTCHA_CHALLENGE', 'LOG_DETAILED'],
        (41, 60, 'ANY'): ['ALERT_AGGREGATED', 'FLAG_FOR_REVIEW'],
        (21, 40, 'ANY'): ['LOG_ONLY', 'DAILY_DIGEST'],
        (0, 20, 'ANY'): ['LOG_ONLY']
    }
    
    def __init__(self):
        self.action_history = []
    
    def calculate_confidence(self, analysis_result: dict) -> str:
        """Calculate confidence level based on multiple signals.
        HIGH: Multiple independent signals agree
        MEDIUM: Single strong signal
        LOW: Weak signals
        """
        rule_triggers = len(analysis_result.get('rule_detection', {}).get('detections', []))
        anomaly_detected = analysis_result.get('anomaly_detection', {}).get('is_anomaly', False)
        anomaly_score = analysis_result.get('anomaly_detection', {}).get('anomaly_score', 0)
        
        # High Confidence: Multiple independent signals agree
        if rule_triggers >= 2 and anomaly_detected:
            return 'HIGH'

        # Medium Confidence: Single strong signal
        if rule_triggers >= 1 or anomaly_score > 50:
            return 'MEDIUM'

        # Low Confidence: Weak signals
        return 'LOW'
    
    def get_response_actions(self, risk_score: float, confidence: str) -> list:
        """Get recommended response actions based on risk score and confidence."""
        for (low, high, conf), actions in self.RESPONSE_MATRIX.items():
            if low <= risk_score <= high:
                if conf == 'ANY' or conf == confidence:
                    return actions
        return ['LOG_ONLY']
    
    def execute_response_action(self, action: str, log_entry: dict, analysis_result: dict) -> dict:
        """Execute individual response action and return action result."""
        action_result = {
            'action': action,
            'timestamp': datetime.now(),
            'status': 'EXECUTED',
            'details': {}
        }
        
        ip = log_entry.get('ip_address')
        user_id = log_entry.get('user_id')
        risk_score = analysis_result.get('risk', {}).get('score', 0)
        
        # AUTO_BLOCK: Block IP for 24 hours
        if action == 'AUTO_BLOCK':
            st.session_state.blocked_ips.add(ip)
            action_result['details'] = {
                'blocked_ip': ip,
                'duration': '24 hours',
                'reason': f'High-risk score ({risk_score:.1f}) triggered automatic block'
            }
        
        # LOCK_ACCOUNT: Lock user account
        elif action == 'LOCK_ACCOUNT':
            if 'locked_accounts' not in st.session_state:
                st.session_state.locked_accounts = {}
            st.session_state.locked_accounts[user_id] = {
                'locked_at': datetime.now(),
                'reason': f'High-risk activity detected (score: {risk_score:.1f})',
                'unlock_token': None
            }
            action_result['details'] = {
                'locked_user': user_id,
                'reason': 'Account locked due to suspicious activity',
                'action_required': 'User must verify identity and reset password'
            }
        
        # EMAIL_USER: Send email notification
        elif action == 'EMAIL_USER':
            action_result['details'] = {
                'recipient': f'{user_id}@example.com',
                'subject': 'Security Alert: Suspicious Activity Detected',
                'body': f'Your account has detected suspicious activity. Risk Score: {risk_score:.1f}. Please verify your identity.'
            }
        
        # ALERT_ADMIN: Alert admin (can be via Telegram, email, etc.)
        elif action == 'ALERT_ADMIN':
            action_result['details'] = {
                'channel': 'Telegram/Email/Dashboard',
                'message': f'ALERT: High-risk activity from {ip} (User: {user_id}, Score: {risk_score:.1f})'
            }
        
        # CHALLENGE_MFA: Require additional MFA verification
        elif action == 'CHALLENGE_MFA':
            action_result['details'] = {
                'user': user_id,
                'method': 'OTP via SMS/Email',
                'note': 'User must complete MFA before proceeding'
            }
        
        # RATE_LIMIT: Reduce rate limit by 50%
        elif action == 'RATE_LIMIT':
            if 'rate_limits' not in st.session_state:
                st.session_state.rate_limits = {}
            st.session_state.rate_limits[ip] = {
                'original_limit': 100,
                'reduced_limit': 50,
                'duration': '1 hour',
                'reason': f'Rate limiting due to risk score {risk_score:.1f}'
            }
            action_result['details'] = {
                'ip': ip,
                'reduction': '50%',
                'new_limit': '50 requests/hour'
            }
        
        # CAPTCHA_CHALLENGE: Challenge with CAPTCHA
        elif action == 'CAPTCHA_CHALLENGE':
            action_result['details'] = {
                'user': user_id,
                'type': 'reCAPTCHA v3',
                'note': 'User must complete CAPTCHA to continue'
            }
        
        # MONITOR_CLOSELY: Add to monitoring queue
        elif action == 'MONITOR_CLOSELY':
            if 'monitored_entities' not in st.session_state:
                st.session_state.monitored_entities = set()
            st.session_state.monitored_entities.add((ip, user_id))
            action_result['details'] = {
                'entity': f'{ip} / {user_id}',
                'monitoring_level': 'ENHANCED',
                'duration': '24 hours'
            }
        
        # FLAG_FOR_REVIEW: Add to manual review queue
        elif action == 'FLAG_FOR_REVIEW':
            if 'review_queue' not in st.session_state:
                st.session_state.review_queue = []
            st.session_state.review_queue.append({
                'ip': ip,
                'user': user_id,
                'score': risk_score,
                'flagged_at': datetime.now()
            })
            action_result['details'] = {
                'queue': 'Manual Review',
                'priority': 'Normal' if risk_score < 60 else 'High'
            }
        
        # ALERT_AGGREGATED: Aggregate alerts (hourly)
        elif action == 'ALERT_AGGREGATED':
            action_result['details'] = {
                'aggregation': 'Hourly',
                'channel': 'Dashboard + Email Digest'
            }
        
        # LOG_DETAILED: Log detailed information
        elif action == 'LOG_DETAILED':
            action_result['details'] = {
                'log_level': 'DEBUG',
                'info_logged': ['Full request', 'User context', 'Behavioral features', 'All detections']
            }
        
        # LOG_ONLY: Log action only
        elif action == 'LOG_ONLY':
            action_result['details'] = {
                'log_level': 'INFO',
                'info_logged': ['Timestamp', 'IP', 'User', 'Risk score']
            }
        
        # DAILY_DIGEST: Add to daily digest report
        elif action == 'DAILY_DIGEST':
            if 'daily_digest_queue' not in st.session_state:
                st.session_state.daily_digest_queue = []
            st.session_state.daily_digest_queue.append({
                'ip': ip,
                'user': user_id,
                'score': risk_score,
                'timestamp': datetime.now()
            })
            action_result['details'] = {
                'report': 'Daily digest',
                'sent_at': 'End of business day'
            }
        
        # REAL_TIME_ALERT: Send real-time alert
        elif action == 'REAL_TIME_ALERT':
            action_result['details'] = {
                'channel': 'Telegram + Dashboard',
                'priority': 'HIGH'
            }
        
        # REVIEW_QUEUE: Add to review queue
        elif action == 'REVIEW_QUEUE':
            if 'review_queue' not in st.session_state:
                st.session_state.review_queue = []
            st.session_state.review_queue.append({
                'ip': ip,
                'user': user_id,
                'score': risk_score,
                'flagged_at': datetime.now(),
                'priority': 'HIGH'
            })
            action_result['details'] = {
                'queue': 'High-Priority Review',
                'priority': 'HIGH'
            }
        
        self.action_history.append(action_result)
        return action_result

    def should_execute_actions(self, risk_score: float, confidence: str) -> bool:
        """Decide whether to execute automated actions for this request.
        Execution policy:
        - Only execute for High/Critical (risk >= 60)
        - Execute for Medium (40-59) only when confidence is HIGH
        - Otherwise skip
        """
        try:
            if risk_score >= 60:
                return True
            if 40 <= risk_score < 60 and confidence == 'HIGH':
                return True
            return False
        except Exception:
            return False

    def get_response_actions_limited(self, risk_score: float, confidence: str, max_actions: int = 2) -> list:
        """Return a limited set of significant response actions (max `max_actions`).
        Prioritize critical actions when trimming.
        """
        actions = self.get_response_actions(risk_score, confidence)
        significant_actions = [a for a in actions if a != 'LOG_ONLY']

        if len(significant_actions) <= max_actions:
            return significant_actions

        # Priority order when limiting
        priority_actions = ['AUTO_BLOCK', 'LOCK_ACCOUNT', 'RATE_LIMIT', 'CHALLENGE_MFA', 'REVIEW_QUEUE']
        limited = []
        for p in priority_actions:
            if p in significant_actions and len(limited) < max_actions:
                limited.append(p)

        # Fill remaining slots with other significant actions in original order
        for a in significant_actions:
            if a not in limited and len(limited) < max_actions:
                limited.append(a)

        return limited


class AlertManager:
    """Simple alert manager with Telegram stub for critical alerts."""
    def __init__(self):
        self.telegram_bot_token = None
        try:
            self.telegram_bot_token = st.secrets.get('TELEGRAM_BOT_TOKEN') if hasattr(st, 'secrets') else None
            self.telegram_chat_id = st.secrets.get('TELEGRAM_CHAT_ID') if hasattr(st, 'secrets') else None
        except Exception:
            self.telegram_bot_token = None
            self.telegram_chat_id = None

    def send_telegram_alert(self, alert_data: dict):
        """Send critical alert to Telegram if token available; otherwise log to UI."""
        msg = (
            f"🚨 CRITICAL SECURITY ALERT\n\nType: {alert_data.get('type')}\n"
            f"Risk Score: {alert_data.get('risk_score')}/100\nTime: {alert_data.get('timestamp')}\n\n"
            f"IP: {alert_data.get('ip')}\nUser: {alert_data.get('user')}\nAction: {alert_data.get('action')}\n"
        )
        if self.telegram_bot_token and self.telegram_chat_id:
            try:
                url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
                requests.post(url, json={'chat_id': self.telegram_chat_id, 'text': msg})
            except Exception as e:
                st.warning(f"Failed to send Telegram alert: {e}")
        else:
            # fallback: show in Streamlit UI console
            try:
                st.warning(msg)
            except Exception:
                print(msg)

    def send_daily_digest(self):
        # Placeholder for daily digest implementation
        return

# =============================================================================
# FUNGSI PEMROSESAN LOG
# =============================================================================

def process_log(log):
    """Memproses log melalui BTDE engine"""
    
    # Cek IP blocking
    if log['ip_address'] in st.session_state.blocked_ips:
        st.session_state.stats['blocked_requests'] += 1
        return
    
    # Analisis dengan BTDE
    result = st.session_state.btde_engine.analyze_log(log)
    
    # Tambahkan informasi ke log
    log['rule_score'] = result['rule_detection']['rule_score']
    log['anomaly_score'] = result['anomaly_detection']['anomaly_score']
    log['total_score'] = result['risk']['score']
    log['risk_level'] = f"{result['risk']['emoji']} {result['risk']['level']}"
    log['risk_color'] = result['risk']['color']
    log['alerts'] = ", ".join(
        result['rule_detection']['alerts'] + 
        result['anomaly_detection']['alerts']
    )
    log['actions'] = ", ".join(result['rule_detection']['actions'])
    
    # Calculate confidence and get automated response actions
    confidence = st.session_state.auto_response_engine.calculate_confidence(result)
    log['confidence'] = confidence
    # Full action set (for auditing) and limited actionable set (for execution)
    full_actions = st.session_state.auto_response_engine.get_response_actions(
        result['risk']['score'], confidence
    )
    limited_actions = st.session_state.auto_response_engine.get_response_actions_limited(
        result['risk']['score'], confidence, max_actions=2
    )

    log['automated_actions'] = full_actions
    log['automated_actions_limited'] = limited_actions

    # Optionally submit IOC to community hub when enabled and high confidence
    try:
        if st.session_state.get('community_enabled') and st.session_state.get('community_client'):
            try:
                client = st.session_state.community_client
                submit_decision = False
                score = result['risk']['score']
                # Submit for critical/high or high-confidence medium
                if score >= 80:
                    submit_decision = True
                elif score >= 60 and confidence == 'HIGH':
                    submit_decision = True

                if submit_decision:
                    indicator = log.get('ip_address')
                    try:
                        # prefer client's anonymization helper if available
                        if hasattr(client, 'anonymize_ip'):
                            indicator = client.anonymize_ip(indicator)
                    except Exception:
                        pass

                    ioc_payload = {
                        'type': 'malicious_ip',
                        'indicator': indicator,
                        'threat_type': [d.get('type') for d in result['rule_detection'].get('detections', [])] or [log.get('simulated_attack_type')],
                        'severity': 'high' if score >= 80 else 'medium',
                        'first_seen': log.get('timestamp').isoformat() if hasattr(log.get('timestamp'), 'isoformat') else str(log.get('timestamp')),
                        'evidence': {
                            'request_uri': log.get('request_uri'),
                            'request_parameters': log.get('request_parameters'),
                            'rule_alerts': result['rule_detection'].get('alerts', []),
                            'anomaly_alerts': result['anomaly_detection'].get('alerts', [])
                        }
                    }
                    resp = client.submit_threat(ioc_payload)
                    log['community_submit'] = resp
            except Exception as e:
                log['community_submit_error'] = str(e)
    except Exception:
        pass

    # Decide whether to execute actions for this request
    should_exec = st.session_state.auto_response_engine.should_execute_actions(
        result['risk']['score'], confidence
    )

    if should_exec and limited_actions:
        executed_count = 0
        for action in limited_actions:
            try:
                action_result = st.session_state.auto_response_engine.execute_response_action(
                    action, log, result
                )
                # Attach a reference to the log so actions can be correlated in exports
                try:
                    action_result.setdefault('related_log', {})
                    action_result['related_log']['ip'] = log.get('ip_address')
                    action_result['related_log']['user'] = log.get('user_id')
                    # store ISO timestamp for reliable matching
                    action_result['related_log']['timestamp'] = getattr(log.get('timestamp'), 'isoformat', lambda: str(log.get('timestamp')))()
                except Exception:
                    pass
                st.session_state.response_actions.append(action_result)
                executed_count += 1
                # Hard cap per request
                if executed_count >= 2:
                    break
            except Exception:
                pass

        # Update stats counters for significant actions (guard keys)
        st.session_state.stats.setdefault('actions_executed', 0)
        st.session_state.stats.setdefault('significant_actions', 0)
        st.session_state.stats['actions_executed'] += executed_count
        st.session_state.stats['significant_actions'] += executed_count
    else:
        # No execution for low-risk or low-confidence events
        pass
    
    # Simpan log
    st.session_state.logs.append(log)
    st.session_state.stats['total_requests'] += 1
    
    # Track traffic type
    if log['type'] == 'normal':
        st.session_state.stats['normal_traffic'] += 1
    else:
        st.session_state.stats['attack_traffic'] += 1
    
    # Tambahkan ke alerts jika berbahaya
    if result['rule_detection']['detected'] or result['anomaly_detection']['is_anomaly']:
        if result['risk']['score'] >= st.session_state.alert_threshold:
            st.session_state.alerts.append(result)
            st.session_state.stats['threats_detected'] += 1

            # Send critical notifications (Telegram) for critical alerts
            try:
                if result['risk']['score'] >= 80:
                    if 'alert_manager' not in st.session_state:
                        st.session_state.alert_manager = AlertManager()
                    alert_payload = {
                        'type': ', '.join([d.get('type','') for d in result['rule_detection'].get('detections', [])]) or 'Rule/Anomaly',
                        'risk_score': result['risk']['score'],
                        'timestamp': str(datetime.now()),
                        'ip': log.get('ip_address'),
                        'user': log.get('user_id'),
                        'action': ','.join(result['rule_detection'].get('actions', [])),
                        'confidence': confidence
                    }
                    st.session_state.alert_manager.send_telegram_alert(alert_payload)
            except Exception:
                pass

    # Autosave to sqlite if enabled
    if st.session_state.autosave_sqlite:
        try:
            save_log_to_sqlite(log)
        except Exception as e:
            st.error(f"Failed to save log to sqlite: {e}")

# =============================================================================
# MAIN APPLICATION
# =============================================================================

def main():
    init_session_state()
    
    # Header
    st.title("🛡️ BTDE - Behavioral Threat Detection Engine")
    st.markdown("""
    **Comprehensive Threat Detection System** | Hybrid Detection (14 Rule-Based + ML Anomaly)  
    Implementasi lengkap untuk UMKM Level 2-3 dengan monitoring real-time dan analytics
    """)
    
    # ==========================================================================
    # SIDEBAR - CONTROL PANEL
    # ==========================================================================
    
    with st.sidebar:
        st.header("⚙️ Control Panel")
        
        # Training Status
        st.subheader("🎯 Model Status")
        if not st.session_state.is_trained:
            st.warning("⚠️ Model belum dilatih")
            if st.button("🎯 Train Model", type="primary", use_container_width=True):
                with st.spinner("Training dengan 100 baseline logs..."):
                    baseline = [st.session_state.traffic_gen.generate_normal_log() for _ in range(100)]
                    success = st.session_state.btde_engine.train_anomaly_model(baseline)
                    if success:
                        st.session_state.is_trained = True
                        st.success("✅ Model trained!")
                        # optionally save model
                        if st.checkbox('Save model to disk after training', value=False, key='save_model_on_train'):
                            ok = save_model(st.session_state.btde_engine.anomaly_model, st.session_state.model_path)
                            if ok:
                                st.info(f'Model saved to {st.session_state.model_path}')
                            else:
                                st.error('Failed to save model')
                        time.sleep(1)
                        st.rerun()
        else:
            st.success("✅ Model Active")

        # Scoring and threshold controls
        st.divider()
        st.subheader('⚖️ Scoring & Thresholds')
        st.session_state.rule_weight = st.slider('Rule weight', 0.1, 3.0, float(st.session_state.rule_weight), step=0.1)
        st.session_state.anomaly_weight = st.slider('Anomaly weight', 0.1, 3.0, float(st.session_state.anomaly_weight), step=0.1)
        st.session_state.alert_threshold = st.slider('Alert threshold (min risk score)', 0, 100, int(st.session_state.alert_threshold))

        st.divider()
        st.subheader('💾 Persistence')
        st.session_state.autosave_sqlite = st.checkbox('Autosave logs to SQLite', value=st.session_state.autosave_sqlite)
        if st.button('Export DB to CSV'):
            try:
                db = _get_db_path()
                if db.exists():
                    conn = sqlite3.connect(str(db))
                    df = pd.read_sql_query('SELECT * FROM logs', conn)
                    conn.close()
                    csv = df.to_csv(index=False).encode('utf-8')
                    st.download_button('Download DB CSV', csv, file_name='btde_logs_db.csv', mime='text/csv')
                else:
                    st.info('No DB file found')
            except Exception as e:
                st.error(f'Failed to export DB: {e}')
        
        st.divider()
        
        # Manual Traffic Generation
        st.subheader("📊 Manual Traffic Control")
        
        col1, col2 = st.columns(2)
        with col1:
            if st.button("✅ Normal", use_container_width=True):
                log = st.session_state.traffic_gen.generate_normal_log()
                process_log(log)
                st.rerun()
        
        with col2:
            if st.button("🔴 Attack", use_container_width=True):
                # If the user selected an exact manual attack type, use it first
                manual_sel = st.session_state.get('manual_attack_type_sel')
                if manual_sel and isinstance(manual_sel, str) and manual_sel.strip() != '':
                    attack_type = manual_sel
                else:
                    # Prefer user-selected attack types from the multiselect (stored in session_state)
                    available = st.session_state.get('attack_types_sel')
                    if available and isinstance(available, (list, tuple)) and len(available) > 0:
                        attack_type = random.choice(available)
                    else:
                        # fallback to full list
                        attack_type = random.choice([
                            'SQLi', 'XSS', 'PathTraversal', 'MaliciousUpload',
                            'BruteForce', 'CredentialStuffing', 'ImpossibleTravel', 'AccountTakeover',
                            'CardTesting', 'HighValueFraud', 'GeographicMismatch', 'VelocityCheck',
                            'BulkDownload', 'OffHoursAccess'
                        ])
                log = st.session_state.traffic_gen.generate_attack_log(attack_type)
                process_log(log)
                st.rerun()
        
        # Manual Attack Type (exact) - optional
        st.markdown("**Manual Attack Type (exact) — leave blank for random selection**")
        manual_attack = st.selectbox(
            "Pilih 1 jenis serangan untuk tombol manual (kosong = random)",
            options=[''] + [
                'SQLi', 'XSS', 'PathTraversal', 'MaliciousUpload',
                'BruteForce', 'CredentialStuffing', 'ImpossibleTravel', 'AccountTakeover',
                'CardTesting', 'HighValueFraud', 'GeographicMismatch', 'VelocityCheck',
                'BulkDownload', 'OffHoursAccess'
            ],
            index=0,
            key='manual_attack_type_sel',
            format_func=lambda x: '(random)' if x == '' else x,
            help='Pilih tipe serangan yang akan dihasilkan ketika menekan tombol manual "Attack". Kosong = acak dari pilihan multiselect atau seluruh daftar.'
        )

        # Attack Type Selection
        st.markdown("**Select Attack Types:**")
        attack_types = st.multiselect(
            "Pilih jenis serangan",
            [
                'SQLi', 'XSS', 'PathTraversal', 'MaliciousUpload',
                'BruteForce', 'CredentialStuffing', 'ImpossibleTravel', 'AccountTakeover',
                'CardTesting', 'HighValueFraud', 'GeographicMismatch', 'VelocityCheck',
                'BulkDownload', 'OffHoursAccess'
            ],
            default=['SQLi', 'BruteForce', 'HighValueFraud', 'BulkDownload'],
            key='attack_types_sel',
            label_visibility="collapsed"
        )
        
        st.divider()
        
        # Auto Simulation
        st.subheader("⚡ Auto Simulation")
        auto_enabled = st.checkbox("Enable Auto Mode")
        
        if auto_enabled:
            log_rate = st.slider("Logs per second", 0.5, 5.0, 1.0)
            attack_prob = st.slider("Attack probability (%)", 5, 50, 20)
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("▶️ Start", use_container_width=True):
                    st.session_state.running = True
                    st.rerun()
            with col2:
                if st.button("⏸️ Stop", use_container_width=True):
                    st.session_state.running = False
                    st.rerun()
        
        st.divider()
        
        # Data Management
        st.subheader("🗂️ Data Management")
        if st.button("🗑️ Clear All Data", type="secondary", use_container_width=True):
            st.session_state.logs = []
            st.session_state.alerts = []
            st.session_state.stats = {
                'total_requests': 0,
                'threats_detected': 0,
                'blocked_requests': 0,
                'normal_traffic': 0,
                'attack_traffic': 0,
                'actions_executed': 0,
                'significant_actions': 0
            }
            st.success("Data cleared!")
            time.sleep(1)
            st.rerun()
        
        st.divider()
        
        # Community Threat Intelligence
        st.subheader("🌐 Community Threat Intelligence")
        st.session_state.community_enabled = st.checkbox(
            "Enable Community Sharing",
            value=st.session_state.community_enabled,
            help="Share detected threats with the community hub and receive IOC updates"
        )
        
        if st.session_state.community_enabled:
            # Generate or store a unique member_id for this client
            if 'community_member_id' not in st.session_state:
                import uuid
                st.session_state.community_member_id = f"member-{str(uuid.uuid4())[:8]}"
            
            st.session_state.community_hub_url = st.text_input(
                "Hub URL",
                value=st.session_state.community_hub_url,
                help="Central hub endpoint (default: http://localhost:8080)"
            )
            st.session_state.community_api_key = st.text_input(
                "API Key (optional)",
                value=st.session_state.community_api_key,
                type="password"
            )
            
            st.caption(f"Member ID: `{st.session_state.community_member_id}`")
            
            # Initialize community client if not already done
            if st.session_state.community_client is None:
                try:
                    from btde_community_client import BTDECommunityClient
                    st.session_state.community_client = BTDECommunityClient(
                        member_id=st.session_state.community_member_id,
                        api_key=st.session_state.community_api_key,
                        hub_url=st.session_state.community_hub_url
                    )
                    st.success("✅ Community client initialized")
                except Exception as e:
                    st.error(f"Failed to initialize community client: {e}")
            
            # Show community stats
            if st.button("🔄 Fetch Community Stats", use_container_width=True):
                try:
                    import requests
                    stats_resp = requests.get(f"{st.session_state.community_hub_url}/api/v1/stats/community")
                    if stats_resp.status_code == 200:
                        stats = stats_resp.json()
                        st.info(f"Community: {stats.get('total_members', 0)} members, {stats.get('total_iocs', 0)} IOCs")
                    else:
                        st.warning("Could not fetch community stats")
                except Exception as e:
                    st.warning(f"Community fetch error: {e}")
        
        st.divider()
        
        # Rules Information
        with st.expander("📋 Detection Rules"):
            st.markdown("""
            **Authentication (A1-A4)**
            - A1: Brute Force
            - A2: Credential Stuffing
            - A3: Impossible Travel
            - A4: Account Takeover
            
            **Web Attacks (W1-W4)**
            - W1: SQL Injection
            - W2: XSS
            - W3: Path Traversal
            - W4: Malicious Upload
            
            **Transaction (T1-T4)**
            - T1: Card Testing
            - T2: High-Value Fraud
            - T3: Geographic Mismatch
            - T4: Velocity Check
            
            **Data Exfiltration (D1-D2)**
            - D1: Bulk Download
            - D2: Off-Hours Access
            
            **+ ML Anomaly Detection**
            """)
    
    # ==========================================================================
    # MAIN DASHBOARD
    # ==========================================================================
    
    # Key Metrics
    col1, col2, col3, col4, col5 = st.columns(5)
    
    with col1:
        st.metric("Total Requests", st.session_state.stats['total_requests'])
    with col2:
        st.metric("Threats Detected", st.session_state.stats['threats_detected'])
    with col3:
        st.metric("Blocked IPs", len(st.session_state.blocked_ips))
    with col4:
        detection_rate = (st.session_state.stats['threats_detected'] / 
                         max(st.session_state.stats['total_requests'], 1)) * 100
        st.metric("Detection Rate", f"{detection_rate:.1f}%")
    with col5:
        block_rate = (st.session_state.stats['blocked_requests'] / 
                     max(st.session_state.stats['total_requests'], 1)) * 100
        st.metric("Block Rate", f"{block_rate:.1f}%")
    
    st.divider()
    
    # Tabs
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
        "🚨 Real-Time Alerts",
        "📋 Log Monitor",
        "📊 Analytics Dashboard",
        "🚫 Blocked IPs",
        "📈 Statistics",
        "⚙️ Automated Responses"
    ])
    
    # ==========================================================================
    # TAB 1: REAL-TIME ALERTS
    # ==========================================================================
    
    with tab1:
        st.subheader("🚨 Active Threat Alerts")
        
        if len(st.session_state.alerts) == 0:
            st.info("✅ No active threats detected")
        else:
            # Filter controls
            col1, col2 = st.columns(2)
            with col1:
                risk_filter = st.multiselect(
                    "Filter by Risk Level",
                    ['Critical', 'High', 'Medium', 'Low'],
                    default=['Critical', 'High']
                )
            with col2:
                show_count = st.slider("Show latest N alerts", 5, 50, 10)
            
            filtered_alerts = [
                alert for alert in reversed(st.session_state.alerts[-show_count:])
                if alert['risk']['level'] in risk_filter
            ]
            
            for alert in filtered_alerts:
                risk_level = alert['risk']['level']
                risk_color = alert['risk']['color']
                risk_score = alert['risk']['score']
                
                with st.container():
                    st.markdown(f"""
                    <div style="padding: 1rem; border-left: 4px solid {risk_color}; 
                                background-color: rgba(0,0,0,0.05); margin-bottom: 1rem; 
                                border-radius: 4px;">
                        <h4 style="margin: 0; color: {risk_color};">
                            🚨 {risk_level} Risk - Score: {risk_score:.1f}/100
                        </h4>
                        <p style="margin: 0.5rem 0;"><strong>Time:</strong> {alert['log']['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}</p>
                        <p style="margin: 0.5rem 0;"><strong>IP:</strong> {alert['log']['ip_address']} | 
                           <strong>User:</strong> {alert['log']['user_id']}</p>
                        <p style="margin: 0.5rem 0;"><strong>Request:</strong> 
                           <code>{alert['log']['request_uri']}</code></p>
                        <p style="margin: 0.5rem 0;"><strong>Attack Type:</strong> 
                           <span style="background: {risk_color}; color: white; padding: 0.2rem 0.5rem; border-radius: 3px;">
                           {alert['log']['simulated_attack_type']}</span></p>
                    """, unsafe_allow_html=True)
                    
                    # Detection Details
                    if alert['rule_detection']['detected']:
                        st.markdown("**🎯 Rule-Based Detections:**")
                        for detection in alert['rule_detection']['detections']:
                            st.markdown(
                                f"- **{detection['type']}** (Rule {detection['rule']}) - "
                                f"Confidence: {detection['confidence']}%"
                            )
                    
                    if alert['anomaly_detection']['is_anomaly']:
                        st.markdown("**🤖 ML Anomaly Detection:**")
                        for alert_msg in alert['anomaly_detection']['alerts']:
                            st.markdown(f"- {alert_msg}")
                    
                    # Actions
                    if alert['rule_detection']['actions']:
                        st.markdown("**⚡ Recommended Actions:**")
                        for action in alert['rule_detection']['actions']:
                            st.markdown(f"- {action}")
                    
                    # Action Buttons
                    col1, col2, col3 = st.columns([1, 1, 3])
                    with col1:
                        if st.button("🚫 Block IP", key=f"block_{alert['log']['timestamp']}"):
                            st.session_state.blocked_ips.add(alert['log']['ip_address'])
                            st.success(f"IP {alert['log']['ip_address']} blocked!")
                            st.rerun()
                    
                    st.markdown("</div>", unsafe_allow_html=True)
    
    # ==========================================================================
    # TAB 2: LOG MONITOR
    # ==========================================================================
    
    with tab2:
        st.subheader("📋 Recent Activity Log")
        
        if len(st.session_state.logs) == 0:
            st.info("No logs yet. Generate traffic from sidebar.")
        else:
            # Display controls
            col1, col2, col3 = st.columns(3)
            with col1:
                show_rows = st.slider("Show rows", 10, 100, 50)
            with col2:
                type_filter = st.multiselect(
                    "Filter by type",
                    [
                        'normal',
                        'SQLi', 'XSS', 'PathTraversal', 'MaliciousUpload',
                        'BruteForce', 'CredentialStuffing', 'ImpossibleTravel', 'AccountTakeover',
                        'CardTesting', 'HighValueFraud', 'GeographicMismatch', 'VelocityCheck',
                        'BulkDownload', 'OffHoursAccess'
                    ],
                    default=[]
                )
            with col3:
                risk_threshold = st.slider("Min risk score", 0, 100, 0)
            
            # Filter logs
            filtered_logs = st.session_state.logs[-show_rows:]
            if type_filter:
                filtered_logs = [log for log in filtered_logs if log['type'] in type_filter]
            if risk_threshold > 0:
                filtered_logs = [log for log in filtered_logs if log['total_score'] >= risk_threshold]
            
            # Create DataFrame
            log_df = pd.DataFrame([
                {
                    'Time': log['timestamp'].strftime('%H:%M:%S'),
                    'IP': log['ip_address'],
                    'User': log['user_id'],
                    'Method': log['request_method'],
                    'URI': log['request_uri'][:40] + '...' if len(log['request_uri']) > 40 else log['request_uri'],
                    'Status': log['status_code'],
                    'Type': log['type'],
                    'Risk Score': f"{log['total_score']:.1f}",
                    'Risk Level': log['risk_level'],
                    'Alerts': log['alerts'][:50] + '...' if len(log['alerts']) > 50 else log['alerts'],
                    'Automated Actions (full)': ','.join(log.get('automated_actions', [])),
                    'Automated Actions (executed)': ','.join(log.get('automated_actions_limited', []))
                }
                for log in reversed(filtered_logs)
            ])
            
            # Style the dataframe
            def color_risk(val):
                if '🔴' in str(val):
                    return 'background-color: #ffcccc'
                elif '🟠' in str(val):
                    return 'background-color: #ffebcc'
                elif '🟡' in str(val):
                    return 'background-color: #ffffcc'
                return ''
            
            # Apply styling only when the DataFrame has the expected column(s)
            if not log_df.empty and 'Risk Level' in log_df.columns:
                styled_df = log_df.style.applymap(color_risk, subset=['Risk Level'])
                st.dataframe(styled_df, use_container_width=True, height=400)
            else:
                # Fallback: show plain dataframe (handles empty or unexpected columns)
                st.dataframe(log_df, use_container_width=True, height=400)
            
            # Download button
            csv = log_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                "📥 Download Log CSV",
                csv,
                "btde_logs.csv",
                "text/csv",
                key='download-csv'
            )
    
    # ==========================================================================
    # TAB 3: ANALYTICS DASHBOARD
    # ==========================================================================
    
    with tab3:
        st.subheader("📊 Threat Analytics & Visualization")
        
        if len(st.session_state.alerts) == 0:
            st.info("No threat data yet. Generate some attacks to see analytics.")
        else:
            # Row 1: Threat Distribution
            col1, col2 = st.columns(2)
            
            with col1:
                # Threat Types Pie Chart
                threat_types = defaultdict(int)
                for alert in st.session_state.alerts:
                    if alert['rule_detection']['detected']:
                        for detection in alert['rule_detection']['detections']:
                            threat_types[detection['type']] += 1
                
                if threat_types:
                    fig = px.pie(
                        values=list(threat_types.values()),
                        names=list(threat_types.keys()),
                        title="Threat Types Distribution",
                        color_discrete_sequence=px.colors.sequential.RdBu
                    )
                    st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                # Risk Level Bar Chart
                risk_levels = defaultdict(int)
                for alert in st.session_state.alerts:
                    risk_levels[alert['risk']['level']] += 1
                
                fig = px.bar(
                    x=list(risk_levels.keys()),
                    y=list(risk_levels.values()),
                    title="Risk Level Distribution",
                    color=list(risk_levels.keys()),
                    color_discrete_map={
                        'Low': '#22c55e',
                        'Medium': '#eab308',
                        'High': '#f59e0b',
                        'Critical': '#dc2626'
                    },
                    labels={'x': 'Risk Level', 'y': 'Count'}
                )
                st.plotly_chart(fig, use_container_width=True)
            
            # Row 2: Time Series
            if len(st.session_state.alerts) > 5:
                risk_scores = [alert['risk']['score'] for alert in st.session_state.alerts[-30:]]
                timestamps = [alert['log']['timestamp'].strftime('%H:%M:%S') 
                             for alert in st.session_state.alerts[-30:]]
                
                fig = go.Figure()
                fig.add_trace(go.Scatter(
                    x=timestamps,
                    y=risk_scores,
                    mode='lines+markers',
                    name='Risk Score',
                    line=dict(color='#dc2626', width=2),
                    marker=dict(size=8)
                ))
                fig.add_hline(y=80, line_dash="dash", line_color="red", 
                             annotation_text="Critical Threshold")
                fig.add_hline(y=60, line_dash="dash", line_color="orange", 
                             annotation_text="High Threshold")
                fig.update_layout(
                    title="Risk Score Timeline (Last 30 Threats)",
                    xaxis_title="Time",
                    yaxis_title="Risk Score",
                    hovermode='x unified'
                )
                st.plotly_chart(fig, use_container_width=True)
            
            # Row 3: Attack Categories
            col1, col2 = st.columns(2)
            
            with col1:
                # Rules triggered
                rules_triggered = defaultdict(int)
                for alert in st.session_state.alerts:
                    if alert['rule_detection']['detected']:
                        for detection in alert['rule_detection']['detections']:
                            rules_triggered[detection['rule']] += 1
                
                if rules_triggered:
                    fig = px.bar(
                        x=list(rules_triggered.keys()),
                        y=list(rules_triggered.values()),
                        title="Most Triggered Rules",
                        labels={'x': 'Rule', 'y': 'Trigger Count'},
                        color=list(rules_triggered.values()),
                        color_continuous_scale='Reds'
                    )
                    st.plotly_chart(fig, use_container_width=True)
            
            with col2:
                # Top attacking IPs
                ip_counts = defaultdict(int)
                for alert in st.session_state.alerts:
                    ip_counts[alert['log']['ip_address']] += 1
                
                top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                
                fig = px.bar(
                    x=[ip for ip, count in top_ips],
                    y=[count for ip, count in top_ips],
                    title="Top 10 Attacking IPs",
                    labels={'x': 'IP Address', 'y': 'Attack Count'},
                    color=[count for ip, count in top_ips],
                    color_continuous_scale='OrRd'
                )
                st.plotly_chart(fig, use_container_width=True)
    
    # ==========================================================================
    # TAB 4: BLOCKED IPs
    # ==========================================================================
    
    with tab4:
        st.subheader("🚫 Blocked IP Management")
        
        if len(st.session_state.blocked_ips) == 0:
            st.info("No IPs currently blocked")
        else:
            st.warning(f"⚠️ {len(st.session_state.blocked_ips)} IP(s) currently blocked")
            
            # iterate over a static list copy to allow removal while iterating
            for ip in list(st.session_state.blocked_ips):
                col1, col2, col3 = st.columns([2, 2, 1])

                with col1:
                    st.markdown(f"🚫 **{ip}**")

                with col2:
                    # Count attacks from this IP
                    attack_count = sum(1 for alert in st.session_state.alerts 
                                      if alert['log']['ip_address'] == ip)
                    st.markdown(f"*Attacks: {attack_count}*")

                with col3:
                    if st.button("Unblock", key=f"unblock_{ip}"):
                        # remove safely and rerun
                        st.session_state.blocked_ips.discard(ip)
                        st.success(f"IP {ip} unblocked!")
                        st.rerun()

                st.divider()
    
    # ==========================================================================
    # TAB 5: STATISTICS
    # ==========================================================================
    
    with tab5:
        st.subheader("📈 System Statistics & Performance")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("### Traffic Statistics")
            st.metric("Total Requests Processed", st.session_state.stats['total_requests'])
            st.metric("Normal Traffic", st.session_state.stats['normal_traffic'])
            st.metric("Attack Traffic", st.session_state.stats['attack_traffic'])
            
            if st.session_state.stats['total_requests'] > 0:
                attack_ratio = (st.session_state.stats['attack_traffic'] / 
                               st.session_state.stats['total_requests']) * 100
                st.metric("Attack Ratio", f"{attack_ratio:.1f}%")
        
        with col2:
            st.markdown("### Detection Performance")
            st.metric("Threats Detected", st.session_state.stats['threats_detected'])
            st.metric("Blocked Requests", st.session_state.stats['blocked_requests'])
            st.metric("Active Blocked IPs", len(st.session_state.blocked_ips))
            
            if st.session_state.stats['attack_traffic'] > 0:
                detection_accuracy = (st.session_state.stats['threats_detected'] / 
                                     st.session_state.stats['attack_traffic']) * 100
                st.metric("Detection Accuracy", f"{detection_accuracy:.1f}%")
            # Actions stats
            st.divider()
            st.markdown("### Response Actions")
            st.metric("Actions Executed", st.session_state.stats.get('actions_executed', 0))
            st.metric("Significant Actions", st.session_state.stats.get('significant_actions', 0))
        
        st.divider()
        
        # Traffic vs Threats Chart
        if len(st.session_state.logs) > 0:
            st.markdown("### Traffic vs Threats Over Time")
            
            # Aggregate data by minute
            time_data = defaultdict(lambda: {'normal': 0, 'threats': 0})
            for log in st.session_state.logs[-100:]:
                time_key = log['timestamp'].strftime('%H:%M')
                if log['total_score'] >= 40:
                    time_data[time_key]['threats'] += 1
                else:
                    time_data[time_key]['normal'] += 1
            
            times = sorted(time_data.keys())
            normal_counts = [time_data[t]['normal'] for t in times]
            threat_counts = [time_data[t]['threats'] for t in times]
            
            fig = go.Figure()
            fig.add_trace(go.Bar(x=times, y=normal_counts, name='Normal', marker_color='#22c55e'))
            fig.add_trace(go.Bar(x=times, y=threat_counts, name='Threats', marker_color='#dc2626'))
            fig.update_layout(
                title="Traffic Distribution",
                xaxis_title="Time",
                yaxis_title="Request Count",
                barmode='stack',
                hovermode='x unified'
            )
            st.plotly_chart(fig, use_container_width=True)
    
    # ==========================================================================
    # TAB 6: AUTOMATED RESPONSES
    # ==========================================================================
    
    with tab6:
        st.subheader("⚙️ Automated Response Actions")
        
        col1, col2 = st.columns(2)
        with col1:
            # Show only significant actions (exclude LOG_ONLY)
            significant_actions_count = sum(1 for a in st.session_state.response_actions if a.get('action') != 'LOG_ONLY')
            st.metric("Significant Actions", significant_actions_count)
        with col2:
            if st.button("🗑️ Clear Response History", key="clear_responses"):
                st.session_state.response_actions = []
                st.session_state.review_queue = []
                st.session_state.locked_accounts = {}
                st.session_state.rate_limits = {}
                st.session_state.monitored_entities = set()
                st.session_state.daily_digest_queue = []
                # reset action stats
                if 'stats' in st.session_state:
                    st.session_state.stats['actions_executed'] = 0
                    st.session_state.stats['significant_actions'] = 0
                st.rerun()
        
        st.divider()
        
        # Display locked accounts
        if len(st.session_state.locked_accounts) > 0:
            st.subheader("🔒 Locked Accounts")
            for user_id, lock_info in st.session_state.locked_accounts.items():
                with st.expander(f"👤 {user_id} - Locked"):
                    st.write(f"**Reason:** {lock_info['reason']}")
                    st.write(f"**Locked At:** {lock_info['locked_at'].strftime('%Y-%m-%d %H:%M:%S')}")
                    if st.button(f"🔓 Unlock {user_id}", key=f"unlock_{user_id}"):
                        del st.session_state.locked_accounts[user_id]
                        st.success(f"Account {user_id} unlocked!")
                        st.rerun()
            st.divider()
        
        # Display rate limits
        if len(st.session_state.rate_limits) > 0:
            st.subheader("⏱️ Rate Limits Applied")
            for ip, limit_info in st.session_state.rate_limits.items():
                with st.expander(f"🌐 {ip}"):
                    st.write(f"**Original Limit:** {limit_info['original_limit']} requests/hour")
                    st.write(f"**Reduced Limit:** {limit_info['reduced_limit']} requests/hour")
                    st.write(f"**Duration:** {limit_info['duration']}")
                    st.write(f"**Reason:** {limit_info['reason']}")
                    if st.button(f"🔄 Reset Rate Limit {ip}", key=f"reset_limit_{ip}"):
                        del st.session_state.rate_limits[ip]
                        st.success(f"Rate limit for {ip} reset!")
                        st.rerun()
            st.divider()
        
        # Display monitored entities
        if len(st.session_state.monitored_entities) > 0:
            st.subheader("👁️ Closely Monitored Entities")
            for ip, user_id in st.session_state.monitored_entities:
                st.markdown(f"- 🌐 **IP:** {ip} | 👤 **User:** {user_id}")
            st.divider()
        
        # Display review queue
        if len(st.session_state.review_queue) > 0:
            st.subheader("📋 Manual Review Queue")
            review_df = pd.DataFrame([
                {
                    'IP': item['ip'],
                    'User': item['user'],
                    'Risk Score': f"{item['score']:.1f}",
                    'Flagged At': item['flagged_at'].strftime('%H:%M:%S'),
                    'Priority': item.get('priority', 'Normal')
                }
                for item in st.session_state.review_queue
            ])
            st.dataframe(review_df, use_container_width=True)
            
            if st.button("✅ Mark All As Reviewed", key="mark_reviewed"):
                st.session_state.review_queue = []
                st.success("Review queue cleared!")
                st.rerun()
            st.divider()
        
        # Display daily digest queue
        if len(st.session_state.daily_digest_queue) > 0:
            st.subheader("📧 Daily Digest Queue")
            digest_df = pd.DataFrame([
                {
                    'IP': item['ip'],
                    'User': item['user'],
                    'Risk Score': f"{item['score']:.1f}",
                    'Timestamp': item['timestamp'].strftime('%H:%M:%S')
                }
                for item in st.session_state.daily_digest_queue[-20:]
            ])
            st.dataframe(digest_df, use_container_width=True)
            st.divider()
        
        # Display action history
        st.subheader("📜 Response Action History")
        if len(st.session_state.response_actions) == 0:
            st.info("No response actions executed yet.")
        else:
            action_filter = st.multiselect(
                "Filter actions by type",
                [
                    'AUTO_BLOCK', 'LOCK_ACCOUNT', 'EMAIL_USER', 'ALERT_ADMIN',
                    'CHALLENGE_MFA', 'RATE_LIMIT', 'CAPTCHA_CHALLENGE', 'MONITOR_CLOSELY',
                    'FLAG_FOR_REVIEW', 'ALERT_AGGREGATED', 'LOG_DETAILED', 'LOG_ONLY',
                    'DAILY_DIGEST', 'REAL_TIME_ALERT', 'REVIEW_QUEUE'
                ],
                default=[]
            )
            
            filtered_actions = st.session_state.response_actions
            if action_filter:
                filtered_actions = [a for a in filtered_actions if a['action'] in action_filter]
            
            for action in reversed(filtered_actions[-30:]):
                with st.container():
                    # Make action column visually wider and status smaller to avoid wrapping
                    col1, col2, col3 = st.columns([4, 1, 1])
                    with col1:
                        # Prevent wrapping of long action names and show bold icon
                        st.markdown(
                            f"<div style='white-space:nowrap; overflow:hidden; text-overflow:ellipsis; font-weight:700;'>⚙️ {action['action']}</div>",
                            unsafe_allow_html=True
                        )
                    with col2:
                        st.markdown(f"<div style='font-size:12px; color:#666'>{action['timestamp'].strftime('%H:%M:%S')}</div>", unsafe_allow_html=True)
                    with col3:
                        # Make status compact
                        st.markdown(f"<div style='font-size:12px; white-space:nowrap'>{action['status']}</div>", unsafe_allow_html=True)
                    
                    with st.expander("📋 Details"):
                        st.json(action['details'])
    
    # ==========================================================================
    # AUTO SIMULATION LOOP
    # ==========================================================================
    
    if st.session_state.running and auto_enabled:
        with st.spinner("Auto simulation running..."):
            is_attack = random.random() * 100 < attack_prob
            
            if is_attack and attack_types:
                attack_type = random.choice(attack_types)
                log = st.session_state.traffic_gen.generate_attack_log(attack_type)
            else:
                log = st.session_state.traffic_gen.generate_normal_log()
            
            process_log(log)
            time.sleep(1 / log_rate)
            st.rerun()

if __name__ == "__main__":
    main()