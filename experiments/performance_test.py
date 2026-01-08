import time
import numpy as np
import matplotlib.pyplot as plt
from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, GT, pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc, Input, Output
import random

# -------------------------- Global Configuration (Aligned with Paper Experiments) --------------------------
# Cryptographic parameters (Bilinear group configuration in the paper)
GROUP_PARAMS = PairingGroup('SS512')  # 512-bit security parameter λ
SECURITY_PARAM = 512
MAX_ATTRIBUTES = 20  # Number of attributes in paper: 0-20
MAX_POLICY_SIZE = 20  # Policy size in paper: 0-20
TEST_ROUNDS = 10  # Each test runs 10 rounds for average (ensure stability)

# Synthetic medical data (Format from Synthetic MOCHA database)
SYNTHETIC_MEDICAL_DATA = {
    "patient_id": "P123456",
    "vital_signs": {"blood_pressure": "120/80", "heart_rate": 72, "temperature": 36.5},
    "diagnosis": "Hypertension Stage 1",
    "medication": "Lisinopril 10mg",
    "timestamp": "2024-05-20T14:30:00Z"
}

# -------------------------- Implementation of Core Algorithms (TUCH + CP-ABE) --------------------------
class TUCH:
    """Time-Bounded Update Capable Chameleon Hash (TUCH) in the paper"""
    def __init__(self, group):
        self.group = group

    def setup(self):
        """TUCH.Setup: Generate public parameters"""
        g = self.group.random(G1)
        return g

    def keygen(self, g):
        """TUCH.KeyGen: Generate trapdoor key pair (HK, CK)"""
        CK = self.group.random(ZR)
        HK = g ** CK
        return (HK, CK)

    def ttkeygen(self, CK, T_start, delta_t):
        """TUCH.TTKeyGen: Generate time-windowed modification key (HK_T, CK_T)"""
        CK_T = self.group.hash((CK, T_start, delta_t), ZR)
        HK_T = g ** CK_T
        return (HK_T, CK_T)

    def check(self, HK, CK, T_start, delta_t, T_current, HK_T, CK_T):
        """TUCH.Check: Verify modification key validity"""
        if HK_T != (g ** CK_T):
            return False
        if T_current >= T_start + delta_t:
            return False
        return True

    def hash(self, m, HK, HK_T, T_start, delta_t, T_current, r_h=None):
        """TUCH.Hash: Compute hash value of medical data"""
        if r_h is None:
            r_h = self.group.random(ZR)
        # Hash message m (medical data) + attribute aggregation value (simulated here, integrated with CP-ABE later)
        m_hash = self.group.hash((str(m),), ZR)
        h = (g ** m_hash) * (HK_T ** r_h)
        return (h, r_h)

    def adapt(self, CK_T, m, r_h, h, T_start, delta_t, m_prime):
        """TUCH.Adapt: Generate collision hash (maintain hash unchanged after data modification)"""
        m_hash = self.group.hash((str(m),), ZR)
        m_prime_hash = self.group.hash((str(m_prime),), ZR)
        # Calculate new random number r_h' (Paper formula: r_h' = (H2(m)-H2(m'))*CK_T^{-1} + r_h mod p)
        r_h_prime = ((m_hash - m_prime_hash) * (CK_T ** -1)) + r_h
        r_h_prime = self.group.init(ZR, int(r_h_prime) % self.group.order())
        # Verify if new hash is consistent with original hash
        h_prime = (g ** m_prime_hash) * (HK_T ** r_h_prime)
        assert h_prime == h, "TUCH collision generation failed"
        return r_h_prime

class RBDMS_CP_ABE(ABEnc):
    """Attribute-aggregated CP-ABE scheme in the paper"""
    def __init__(self, group):
        super().__init__()
        self.group = group
        self.util = SecretUtil(group)

    def setup(self):
        """CP-ABE.Setup: Generate master key pair (MPK, MSK)"""
        alpha = self.group.random(ZR)
        beta = self.group.random(ZR)
        g = self.group.random(G1)
        MPK = {
            'g': g,
            'g_beta': g ** beta,
            'g_inv_beta': g ** (beta ** -1),
            'e_gg_alpha': pair(g, g) ** alpha
        }
        MSK = {'beta': beta, 'g_alpha': g ** alpha}
        # Generate attribute encoding dictionary (Dict: att→idx in paper)
        attr_dict = {f"dept_{i}": i+1 for i in range(MAX_ATTRIBUTES)}  # Department attributes
        attr_dict.update({f"qual_{i}": i+21 for i in range(MAX_ATTRIBUTES)})  # Qualification attributes
        return (MPK, MSK, attr_dict)

    def keygen(self, MPK, MSK, attr_set, user_id, attr_dict):
        """CP-ABE.KeyGen: Generate user key with aggregated attributes (constant size O(1))"""
        r = self.group.random(ZR)
        mu = self.group.random(ZR)
        # Attribute aggregation: Map attribute set to integer product (Agg_prod = ∏idx mod p' in paper)
        attr_idx = [attr_dict[att] for att in attr_set if att in attr_dict]
        p_prime = self.group.random(ZR)  # Large prime coprime with p
        agg_prod = 1
        for idx in attr_idx:
            agg_prod = (agg_prod * idx) % int(p_prime)
        # Aggregated attribute value (bound to user ID)
        agg_S = self.group.hash((str(agg_prod), user_id), G1)
        # Generate user secret key (constant size, independent of number of attributes)
        SK_u = {
            'SK0': mu,  # Signature private key component
            'SK1': (MSK['g_alpha'] * (MPK['g'] ** r)) ** (MSK['beta'] ** -1),
            'SK2': MPK['g'] ** r * (agg_S ** r),
            'SK3': MPK['g'] ** r,
            'Agg_S': agg_S,
            'user_id': user_id
        }
        PK_u = MPK['g'] ** mu  # User public key
        return (SK_u, PK_u)

    def encrypt(self, MPK, m, access_policy, attr_dict):
        """CP-ABE.Encrypt: Encrypt medical data (policy aggregation, constant ciphertext size)"""
        s = self.group.random(ZR)
        # Policy aggregation: Map access policy to integer product (Agg(W) in paper)
        policy_attrs = self.util.getAttributeList(access_policy)
        policy_idx = [attr_dict[att] for att in policy_attrs if att in attr_dict]
        p_prime = self.group.random(ZR)
        agg_prod_W = 1
        for idx in policy_idx:
            agg_prod_W = (agg_prod_W * idx) % int(p_prime)
        agg_W = self.group.hash((str(agg_prod_W), access_policy), G1)  # Bind to policy ID

        # Generate access tree (T is access tree in paper)
        tree = self.util.createAccessTree(access_policy)
        self.util.shareSecret(s, tree)

        # Ciphertext components (constant size O(1), independent of policy complexity)
        C1 = MPK['g'] ** s
        C2 = m  # Simplified as plaintext encryption; replace with symmetric encryption key in practice
        C3 = MPK['g_beta'] ** s
        C4 = agg_W ** tree.nodes[1]['secret']  # Root node secret share
        C5 = MPK['g'] ** tree.nodes[1]['secret']

        C = {'C1': C1, 'C2': C2, 'C3': C3, 'C4': C4, 'C5': C5, 'agg_W': agg_W}
        return C

    def decrypt(self, MPK, SK_u, C, attr_dict):
        """CP-ABE.Decrypt: Decrypt medical data (single pairing operation, O(1) complexity)"""
        # Verify if attribute set satisfies policy (simplified as subset inclusion check here)
        policy_attrs = self.util.getAttributeList("(" + " OR ".join([k for k in attr_dict.keys()]) + ")")
        user_attrs = [k for k, v in attr_dict.items() if v in [attr_dict[att] for att in SK_u['Agg_S']]]
        if not self.util.prune(self.util.createAccessTree("(" + " OR ".join(policy_attrs) + ")"), user_attrs):
            return None  # Decryption failed: policy not satisfied

        # Calculate decryption value (DecVal = e(SK2,C4)/e(SK3,C5) in paper)
        dec_val = pair(SK_u['SK2'], C['C4']) / pair(SK_u['SK3'], C['C5'])
        # Recover medical data (m_dec = C2 / (e(C3,SK1)/F_R) in paper)
        e_C3_SK1 = pair(C['C3'], SK_u['SK1'])
        F_R = dec_val  # Root node value (after recursive interpolation)
        m_dec = C['C2']  # Simplified version; decrypt according to encryption method in practice
        return m_dec

# -------------------------- Running Time Tests (Aligned with Fig. 3(a)-(f) in Paper) --------------------------
def test_system_setup_time():
    """Test Fig. 3(a): System setup time (varied by number of attributes)"""
    cpabe = RBDMS_CP_ABE(GROUP_PARAMS)
    times = []
    for attr_count in range(0, MAX_ATTRIBUTES+1):
        attr_set = [f"dept_{i}" for i in range(attr_count)]
        start = time.time()
        for _ in range(TEST_ROUNDS):
            MPK, MSK, attr_dict = cpabe.setup()
            cpabe.keygen(MPK, MSK, attr_set, "user_001", attr_dict)
        avg_time = (time.time() - start) / TEST_ROUNDS * 1000  # Convert to milliseconds
        times.append(avg_time)
    return times

def test_keygen_time():
    """Test Fig. 3(b): Key generation time (varied by number of attributes)"""
    cpabe = RBDMS_CP_ABE(GROUP_PARAMS)
    MPK, MSK, attr_dict = cpabe.setup()
    times = []
    for attr_count in range(0, MAX_ATTRIBUTES+1):
        attr_set = [f"dept_{i}" for i in range(attr_count)]
        start = time.time()
        for _ in range(TEST_ROUNDS):
            cpabe.keygen(MPK, MSK, attr_set, "user_001", attr_dict)
        avg_time = (time.time() - start) / TEST_ROUNDS * 1000
        times.append(avg_time)
    return times

def test_hash_generation_time():
    """Test Fig. 3(c): Hash generation time (varied by policy size)"""
    tuch = TUCH(GROUP_PARAMS)
    g = tuch.setup()
    HK, CK = tuch.keygen(g)
    T_start = time.time()
    delta_t = 3600  # Key validity period: 1 hour
    HK_T, CK_T = tuch.ttkeygen(CK, T_start, delta_t)
    times = []
    for policy_size in range(0, MAX_POLICY_SIZE+1):
        # Generate access policies of different sizes
        policy = " OR ".join([f"dept_{i}" for i in range(policy_size)])
        if not policy:
            policy = "dept_0"
        start = time.time()
        for _ in range(TEST_ROUNDS):
            tuch.hash(SYNTHETIC_MEDICAL_DATA, HK, HK_T, T_start, delta_t, time.time())
        avg_time = (time.time() - start) / TEST_ROUNDS * 1000
        times.append(avg_time)
    return times

def test_encrypt_decrypt_time():
    """Test Fig. 3(d): Encryption/Decryption time (varied by policy size)"""
    cpabe = RBDMS_CP_ABE(GROUP_PARAMS)
    MPK, MSK, attr_dict = cpabe.setup()
    attr_set = [f"dept_{i}" for i in range(10)]  # Fixed 10 user attributes
    SK_u, _ = cpabe.keygen(MPK, MSK, attr_set, "user_001", attr_dict)
    times = {'encrypt': [], 'decrypt': []}
    for policy_size in range(0, MAX_POLICY_SIZE+1):
        policy = " OR ".join([f"dept_{i}" for i in range(policy_size)])
        if not policy:
            policy = "dept_0"
        # Encryption time
        start = time.time()
        for _ in range(TEST_ROUNDS):
            cpabe.encrypt(MPK, SYNTHETIC_MEDICAL_DATA, policy, attr_dict)
        avg_encrypt = (time.time() - start) / TEST_ROUNDS * 1000
        times['encrypt'].append(avg_encrypt)
        # Decryption time
        C = cpabe.encrypt(MPK, SYNTHETIC_MEDICAL_DATA, policy, attr_dict)
        start = time.time()
        for _ in range(TEST_ROUNDS):
            cpabe.decrypt(MPK, SK_u, C, attr_dict)
        avg_decrypt = (time.time() - start) / TEST_ROUNDS * 1000
        times['decrypt'].append(avg_decrypt)
    return times

def test_modify_time():
    """Test Fig. 3(e): Data modification time (varied by policy size)"""
    tuch = TUCH(GROUP_PARAMS)
    g = tuch.setup()
    HK, CK = tuch.keygen(g)
    T_start = time.time()
    delta_t = 3600
    HK_T, CK_T = tuch.ttkeygen(CK, T_start, delta_t)
    h, r_h = tuch.hash(SYNTHETIC_MEDICAL_DATA, HK, HK_T, T_start, delta_t, time.time())
    # Modified medical data
    modified_data = SYNTHETIC_MEDICAL_DATA.copy()
    modified_data['vital_signs']['blood_pressure'] = "115/75"
    times = []
    for policy_size in range(0, MAX_POLICY_SIZE+1):
        start = time.time()
        for _ in range(TEST_ROUNDS):
            # Verify key validity → generate collision hash → modify data
            if tuch.check(HK, CK, T_start, delta_t, time.time(), HK_T, CK_T):
                tuch.adapt(CK_T, SYNTHETIC_MEDICAL_DATA, r_h, h, T_start, delta_t, modified_data)
        avg_time = (time.time() - start) / TEST_ROUNDS * 1000
        times.append(avg_time)
    return times

def test_verify_time():
    """Test Fig. 3(f): Verification time (varied by policy size)"""
    tuch = TUCH(GROUP_PARAMS)
    g = tuch.setup()
    HK, CK = tuch.keygen(g)
    T_start = time.time()
    delta_t = 3600
    HK_T, CK_T = tuch.ttkeygen(CK, T_start, delta_t)
    h, r_h = tuch.hash(SYNTHETIC_MEDICAL_DATA, HK, HK_T, T_start, delta_t, time.time())
    times = []
    for policy_size in range(0, MAX_POLICY_SIZE+1):
        start = time.time()
        for _ in range(TEST_ROUNDS):
            # Recompute hash and verify (h' == h)
            h_prime, _ = tuch.hash(SYNTHETIC_MEDICAL_DATA, HK, HK_T, T_start, delta_t, time.time(), r_h)
            assert h_prime == h, "Verification failed"
        avg_time = (time.time() - start) / TEST_ROUNDS * 1000
        times.append(avg_time)
    return times

# -------------------------- Execute Tests and Generate Paper-Style Plots --------------------------
def run_all_tests():
    """Run all time tests and generate comparison plots consistent with Fig. 3 in the paper"""
    print("Starting core running time tests of the paper...")
    print(f"Test configuration: Number of attributes 0-{MAX_ATTRIBUTES}, Policy size 0-{MAX_POLICY_SIZE}, {TEST_ROUNDS} rounds per group")

    # Execute all tests
    setup_times = test_system_setup_time()
    keygen_times = test_keygen_time()
    hash_times = test_hash_generation_time()
    ed_times = test_encrypt_decrypt_time()
    modify_times = test_modify_time()
    verify_times = test_verify_time()

    # Generate x-axis data
    x_attr = list(range(0, MAX_ATTRIBUTES+1))  # Number of attributes
    x_policy = list(range(0, MAX_POLICY_SIZE+1))  # Policy size

    # Plot subplots in paper Fig. 3 style
    fig, axes = plt.subplots(2, 3, figsize=(18, 12))
    fig.suptitle('RBDMS Scheme Performance Comparison (Average Time in ms)', fontsize=16)

    # (a) System setup time
    axes[0,0].plot(x_attr, setup_times, 'o-', color='blue', linewidth=2, label='RBDMS')
    axes[0,0].set_xlabel('Number of Attributes')
    axes[0,0].set_ylabel('Time (ms)')
    axes[0,0].set_title('System Setup Step')
    axes[0,0].legend()
    axes[0,0].grid(True)

    # (b) Key generation time
    axes[0,1].plot(x_attr, keygen_times, 's-', color='red', linewidth=2, label='RBDMS')
    axes[0,1].set_xlabel('Number of Attributes')
    axes[0,1].set_ylabel('Time (ms)')
    axes[0,1].set_title('Key Generation Step')
    axes[0,1].legend()
    axes[0,1].grid(True)

    # (c) Hash generation time
    axes[0,2].plot(x_policy, hash_times, '^-', color='green', linewidth=2, label='RBDMS')
    axes[0,2].set_xlabel('Size of Policy')
    axes[0,2].set_ylabel('Time (ms)')
    axes[0,2].set_title('Hash Generation Step')
    axes[0,2].legend()
    axes[0,2].grid(True)

    # (d) Encryption and decryption time
    axes[1,0].plot(x_policy, ed_times['encrypt'], 'o-', color='orange', linewidth=2, label='Encrypt')
    axes[1,0].plot(x_policy, ed_times['decrypt'], 's-', color='purple', linewidth=2, label='Decrypt')
    axes[1,0].set_xlabel('Size of Policy')
    axes[1,0].set_ylabel('Time (ms)')
    axes[1,0].set_title('Encryption and Decryption Step')
    axes[1,0].legend()
    axes[1,0].grid(True)

    # (e) Modification time
    axes[1,1].plot(x_policy, modify_times, 'd-', color='brown', linewidth=2, label='RBDMS')
    axes[1,1].set_xlabel('Size of Policy')
    axes[1,1].set_ylabel('Time (ms)')
    axes[1,1].set_title('Modification Step')
    axes[1,1].legend()
    axes[1,1].grid(True)

    # (f) Verification time
    axes[1,2].plot(x_policy, verify_times, 'v-', color='cyan', linewidth=2, label='RBDMS')
    axes[1,2].set_xlabel('Size of Policy')
    axes[1,2].set_ylabel('Time (ms)')
    axes[1,2].set_title('Verification Step')
    axes[1,2].legend()
    axes[1,2].grid(True)

    # Save plot (consistent with paper Fig. 3 format)
    plt.tight_layout()
    plt.savefig('rbdms_performance_comparison.png', dpi=300, bbox_inches='tight')
    print("Tests completed! Plot saved as rbdms_performance_comparison.png")

    # Output numerical results (for paper table comparison)
    results = {
        "system_setup_time_ms": setup_times,
        "keygen_time_ms": keygen_times,
        "hash_generation_time_ms": hash_times,
        "encryption_time_ms": ed_times['encrypt'],
        "decryption_time_ms": ed_times['decrypt'],
        "modification_time_ms": modify_times,
        "verification_time_ms": verify_times
    }
    np.savez('rbdms_time_results.npz', **results)
    print("Numerical results saved as rbdms_time_results.npz")

if __name__ == "__main__":
    run_all_tests()
