"""

Fighting the Cacherssssssssssssssss woooooo
Run with:  python main.py

1) content  2) game rules  3) aes engine  4) ui helpers  5) screens  6) app

"""
import tkinter as tk
from dataclasses import dataclass, field
from pathlib import Path #added by copilot to make it scrollable
from tkinter import ttk
from typing import Optional
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ------------------- content -------------------
INTRO = [
    ("Welcome to Fighting the Cachers!", 
    "On their own, encryption schemes like AES are nothing more than theoretical algorithms. For them to encrypt electronic messages, they must be implemented, either in software or in hardware. In this game, your goal is to implement the AES encryption algorithm in a way that is performant and secure against cache leakages.", 
    "What is AES?", 
    "AES, or the Advanced Encryption Standard, is the National Institute of Standards and Technology’s symmetric key encryption algorithm of choice for encrypting electronic data. AES is used by two parties who share a single secret key to encrypt and decrypt messages. AES takes blocks of data and encrypts them with a secret key, using confusion to obscure the relationship between the key/message and resulting ciphertext, as well as using diffusion to spread the influence of the message across the ciphertext."
    ),
    ("What does AES do?",
     "As an algorithm, AES has 4 major steps:",
     "-  a nonlinear function SubBytes",
     "-  a rearranging of message bytes in ShiftRows", 
     "-  a linear matrix multiplication in MixColumns", 
     "-  and the application of the secret key in AddRoundKey.",
     "These 4 steps make up a “Round” of AES, with many rounds being performed in series to encrypt a single block of the message. The number of rounds used depends on the length of your secret key. For example, AES-128 uses a 128-bit secret key and has 10 rounds, while AES-256 uses a 256-bit secret key and has 14 rounds.",
    "When we talk about the AES algorithm, it is defined by these 4 steps and ways they come together in a series of rounds. Any implementation of AES in code or in hardware will all perform these steps. How they perform these steps is where implementations come into their own."
    ),
    ("What is the performance of an AES implementation?",
     "When we discuss the performance of an AES implementation here, we are referring to the time required to encrypt messages. Implementations with higher performance will compute the steps in AES faster than those with a lower performance.",
     "What are cache timing leakages?",
     "To speed up the reading of data from memory, computers make use of caches. Caches temporarily store data that has been accessed recently, such that, if the data is needed again the processor can read it from the cache instead of a slower memory component. If the required data can be found in a cache, it is called a “cache hit,” while if the data cannot be found in the cache, it is called a “cache miss.” By nature, cache hits are faster memory accesses than cache misses.",

     "Adversaries to a computer system can use cache hits and cache misses to learn what data has been stored in the cache recently. They can record the time required to run a program, such as AES, to determine if a cache hit or cache miss occurred. These “cache timing leakages” can allow an adversary to learn the access patterns of lookup tables.",
     
     ),
    ("The role of lookup tables",
    "In AES, lookup tables are often used to speed up computation. This increases the risk of cache timing leakages. The amount of information revealed through cache timing leakages can be reduced, but it often comes with a tradeoff and is entirely dependent on how AES has been implemented.",
    "It is your task now to investigate those tradeoffs. You will now design an AES implementation that is both performant and resistant to cache timing leakages."
     ),
]

DECISION_INFO = {
    "sbox": {
        "title": "Decision 1: 'Sub' me in coach!",
        "prompt": "Determine how your system handles the SubBytes operation. Choose carefully...",
        True: ("Use S-boxes for SubBytes", "Pre-compute the non-linear substitutions applied in SubBytes when setting up AES. The substitutions are stored as a lookup table in memory. This lookup table, called an S-box, is 256 bytes in size and can fit into 4 lines of the cache. Which value is accessed in the S-box depends on the input value, which is a combination of the secret round key with either the plaintext message or the output of a previous round."),
        False: ("Compute SubBytes Manually", "The substitutions applied in SubBytes can be numerically computed as an inversion in a Galois Field. Compared to the simpler computations in ShiftRows, MixColumns, and AddRoundKey, the inverse over a Galois Field is the most complicated part of an AES round."),
    },
    "ttable": {
        "title": "Decision 2: To T or not to T...",
        "prompt": "Will you choose to use T-tables or stick with the traditional route?",
        True: ("Use T-tables for Each Round", "Similar to how S-boxes precompute the substitutions in SubBytes, T-tables precompute the computation of most of an entire round of AES. SubBytes, ShiftRows, and MixColumns are replaced with a memory table lookup, leaving only AddRoundKey to be performed in real time. Just as in S-boxes, the accessed value of the T-table lookup depends on the round key and either the plaintext message or the output of the previous round. To include the computation of ShiftRows and MixColumns, each T-table is 4 times the size of an S-box. This means they take up 16 lines on a cache instead of an S-box’s 4 lines."),
        False: ("Perform Rounds Normally", "On the fly in each round, perform the logical computations to implement ShiftRows and MixColumns. ShiftRows is a simple reordering of bytes, and MixColumns is a matrix multiplication with a fixed array."),
    },
    "masking": {
        "title": "Decision 3: Mask off, hold up Mask on?",
        "prompt": "Is masking what you need, or is it better to keep things the same? You decide.",
        True: ("Use Boolean Masking for Memory Accesses", "Boolean Masking was originally created as a power-analysis countermeasure. Every intermediate value in AES is XORed with a random mask. All lookup tables are recomputed based on the mask, and any single lookup is uniformly random. This does not necessarily prevent cache attacks, but does work to obfuscate the absolute index of lookups. Applying a mask requires pseudorandom values to be generated and each lookup table to be recomputed, adding computation. It is possible to reuse masks for multiple lookups to reduce the computation, however this prevents the lookups from being uniformly random."),
        False: ("Perform Memory Accesses as Usual", "All accesses to data in the cache are performed normally, with no masking."),
    },
    "hw": {
        "title": "Decision 4: Chip decisions but not talking about Doritos vs Lays",
        "prompt": "They finally released that fancy new chip, I hope your computer can handle it...",
        True: ("Use a Special Instruction Chip", "Use a specialized chip that has been designed to execute AES efficiently. Examples include AES-NI from Intel and ARM Crypto. Each comes with dedicated instructions to execute AES round operations efficiently. Each of the round operations are implemented directly in hardware, rather than using general purpose arithmetic logic and instructions."),
        False: ("Use a Standard Processor", "Use a general purpose processor to run your AES implementation. Some operations required in AES like XOR, shifting, and data movement are handled by existing logic and instructions. Other operations, like the Galois Field arithmetic of SubBytes and MixColumns are not commonly used by ALUs and must be implemented as a combination of smaller instructions. Using more instructions generally increases the runtime of a program."),
    },
}

# (decision, value) -> (performance effect, cache-security effect) for the results screen
EFFECTS = {
    ("sbox", True): ("placeholder_performance_effect_1", "placeholder_security_effect_1"),
    ("sbox", False): ("placeholder_performance_effect_2", "placeholder_security_effect_2"),
    ("ttable", True): ("placeholder_performance_effect_3", "placeholder_security_effect_3"),
    ("ttable", False): ("placeholder_performance_effect_4", "placeholder_security_effect_4"),
    ("masking", True): ("placeholder_performance_effect_5", "placeholder_security_effect_5"),
    ("masking", False): ("placeholder_performance_effect_6", "placeholder_security_effect_6"),
    ("hw", True): ("placeholder_performance_effect_7", "placeholder_security_effect_7"),
    ("hw", False): ("placeholder_performance_effect_8", "placeholder_security_effect_8"),
}

# QUESTION PLACEHOLDERS: replace with real questions
# Each question: dict(q=text, options=[...], answer=index of correct option, explanation=text)
def placeholder_question(n):
    return dict(q="Implementing SubBytes with S-box lookup tables will most likely…",
                options=["Improve performance, but potentially expose secret-dependent memory accesses to cache attacks.", " Reduce performance and automatically prevent cache attacks", "Improve performance and eliminate all implementation-level vulnerabilities.", "Change the mathematical operations that define AES."],
                answer=0, explanation="Lookup tables can speed up SubBytes, but the accessed location can depend on secret-related intermediate values. Cache observations may reveal information about those accesses.")
dict(q="If you compute the SubBytes transformation mathematically instead of using an S-box lookup table, what is the most likely tradeoff?",
                options=["Higher performance because all mathematical operations are faster than memory accesses.", " Potentially more computation, but less reliance on secret-dependent table accesses.", "No change in performance or cache behavior because AES is unchanged.", "Guaranteed immunity to every cache attack, regardless of how the computation is implemented."],
                answer=1, explanation="Computing the finite-field transformation can require more instructions than a table lookup. It can avoid the particular leakage mechanism caused by secret-dependent table accesses, provided the computation itself is implemented appropriately. Arithmetic alone does not guarantee constant-time execution.")
dict(q="Compared with an S-box lookup implementation, using T-tables to combine several AES round operations will most likely…",
                options=["Require fewer table lookups, use less cache space, and eliminate cache leakage.", " Replace the entire AES algorithm with a different encryption algorithm.", "Potentially speed up round processing, but use larger tables and expose more cache locations to secret-dependent accesses.", "Make AES slower while guaranteeing that every memory access is independent of the secret key."],
                answer=2, explanation="T-tables combine work from multiple AES transformations, potentially reducing instruction overhead. However, they occupy more cache space than S-box tables and still use secret-dependent lookups, which can create cache leakage.")
dict(q="If you perform ShiftRows and MixColumns as separate operations instead of combining them into T-tables, what should you expect?",
                options=["More explicit computation, but less reliance on large T-table lookups.", "Guaranteed faster execution and complete protection against cache attacks.", " Elimination of all memory accesses during AES encryption.", "A change to AES's underlying encryption algorithm."],
                answer=0, explanation=" Performing the transformations requires more instructions than using T-tables. It avoids the large combined tables, but it does not necessarily eliminate cache leakage if the implementation still uses an S-box lookup table.")
dict(q="What is a likely tradeoff when you use Boolean masking for lookup-table accesses?",
                options=["It makes every AES operation faster without requiring additional computation.", "It makes the AES key longer and therefore harder to guess.", "It can make lookup patterns harder to interpret, but generating masks and adapting tables adds computation.", "It guarantees that the attacker can never learn anything from the cache."],
                answer=2, explanation="Boolean masking uses random values to obscure intermediate AES values and adapt lookup tables. This can make the relationship between secret values and observed lookup patterns harder to interpret. However, generating masks and adapting tables adds computational overhead.")
dict(q="If lookup-table accesses are performed normally, without masking, what opportunity might this give an attacker?",
                options=["The attacker can automatically read every encrypted message as plaintext.", "The attacker can use cache timing differences to investigate which lookup-table locations were accessed.", "The attacker can make AES skip its AddRoundKey operation.", "The attacker can prevent the processor from using its cache."],
                answer=1, explanation="When lookup-table accesses are performed normally, their locations may depend on secret-related values. Because cache hits and misses take different amounts of time, an attacker may measure timing differences to infer which table locations were accessed. These observations can reveal information, but do not automatically expose the plaintext or the entire secret key.")
dict(q="What is a likely advantage of using specialized AES instructions, such as AES-NI or ARM Crypto extensions?",
                options=["They change AES into a stronger encryption algorithm.", "They guarantee protection against every possible attack.", "They allow AES to run without any processor hardware.", "They can execute AES operations efficiently using dedicated hardware, reducing the work required from ordinary software instructions."],
                answer=3, explanation="Specialized instructions such as AES-NI and ARM Crypto extensions allow compatible processors to perform AES operations using dedicated hardware. This can reduce the number of ordinary software instructions needed and improve encryption performance. These instructions can also avoid the classic cache-leakage mechanism associated with secret-dependent software lookup tables, but they do not eliminate every possible vulnerability.")
dict(q="What is a likely consequence of implementing AES on a standard processor without dedicated AES instructions?",
                options=["AES cannot be implemented correctly on that processor.", "AES may require more ordinary instructions to perform its operations, increasing the time needed to encrypt messages.", "AES automatically becomes resistant to cache timing attacks.", "AES no longer needs to perform SubBytes, ShiftRows, MixColumns, or AddRoundKey."],
                answer=1, explanation="Without dedicated AES instructions, a general-purpose processor may need to execute multiple ordinary instructions to perform AES operations such as SubBytes and MixColumns. This can increase encryption time compared with hardware-accelerated AES. The processor can still implement AES correctly, and its vulnerability to cache attacks depends on the implementation—for example, whether it uses secret-dependent lookup tables.")
dict(q="Why can two systems use the same AES algorithm but have different encryption performance?",
                options=["Each system uses a different mathematical encryption algorithm, even if both are called AES.", "Different implementations can perform AES operations differently, such as using lookup tables, ordinary processor instructions, or specialized AES hardware.", "A system that encrypts messages more slowly must use a longer AES key.", "The AES algorithm automatically changes its number of operations depending on how fast the processor is."],
                answer=1, explanation="AES defines the encryption operations, but implementations can execute those operations in different ways. Lookup tables and specialized processor instructions can improve performance, while computing operations using ordinary instructions may require more work.")
dict(q="Why can an AES implementation that uses lookup tables be vulnerable to cache timing attacks?",
                options=["Lookup tables store the secret key in plaintext, allowing an attacker to read it directly.", "Lookup tables cause AES to skip some encryption rounds, making the ciphertext easier to decrypt.", "The locations accessed in a lookup table can depend on secret-related values, and those accesses can affect observable cache timing.", "Lookup tables prevent the processor from using its cache efficiently, making all memory accesses slower."],
                answer=2, explanation="The memory locations accessed during AES may depend on intermediate values involving the secret key. Because cache hits and misses take different amounts of time, an attacker may use timing observations to infer information about the lookup patterns and potentially the key.")
dict(q="How can an attacker use differences between cache hits and cache misses to learn information about an AES computation?",
                options=["By measuring execution times and using timing differences to infer which memory locations were accessed.", "By reading every value stored in the processor's cache without interacting with the system.", "By making cache misses change the mathematical operations performed by AES.", "By forcing AES to encrypt messages without using its secret key."],
                answer=0, explanation="Cache hits are generally faster than cache misses. By measuring timing differences across repeated operations, an attacker may infer memory access patterns and learn information about secret-dependent computations. This does not automatically reveal the entire secret key or plaintext.")
# Prediction phase: one question per decision the student made (numbered in order shown).
# To write real ones, build them in PredictScreen from the student's choice (see that class).
NUM_ASSESSMENT_QUESTIONS = 10
ASSESSMENT = [placeholder_question(n) for n in range(1, NUM_ASSESSMENT_QUESTIONS + 1)]

# Questions are selected by the implementation decision and the player's choice.
PREDICTION_QUESTIONS = {
    ("sbox", True): dict(q="Implementing SubBytes with S-box lookup tables will most likely…",
        options=["Improve performance, but potentially expose secret-dependent memory accesses to cache attacks.", " Reduce performance and automatically prevent cache attacks", "Improve performance and eliminate all implementation-level vulnerabilities.", "Change the mathematical operations that define AES."],
        answer=0, explanation="Lookup tables can speed up SubBytes, but the accessed location can depend on secret-related intermediate values. Cache observations may reveal information about those accesses."),
    ("sbox", False): dict(q="If you compute the SubBytes transformation mathematically instead of using an S-box lookup table, what is the most likely tradeoff?",
        options=["Higher performance because all mathematical operations are faster than memory accesses.", " Potentially more computation, but less reliance on secret-dependent table accesses.", "No change in performance or cache behavior because AES is unchanged.", "Guaranteed immunity to every cache attack, regardless of how the computation is implemented."],
        answer=1, explanation="Computing the finite-field transformation can require more instructions than a table lookup. It can avoid the particular leakage mechanism caused by secret-dependent table accesses, provided the computation itself is implemented appropriately. Arithmetic alone does not guarantee constant-time execution."),
    ("ttable", True): dict(q="Compared with an S-box lookup implementation, using T-tables to combine several AES round operations will most likely…",
        options=["Require fewer table lookups, use less cache space, and eliminate cache leakage.", " Replace the entire AES algorithm with a different encryption algorithm.", "Potentially speed up round processing, but use larger tables and expose more cache locations to secret-dependent accesses.", "Make AES slower while guaranteeing that every memory access is independent of the secret key."],
        answer=2, explanation="T-tables combine work from multiple AES transformations, potentially reducing instruction overhead. However, they occupy more cache space than S-box tables and still use secret-dependent lookups, which can create cache leakage."),
    ("ttable", False): dict(q="If you perform ShiftRows and MixColumns as separate operations instead of combining them into T-tables, what should you expect?",
        options=["More explicit computation, but less reliance on large T-table lookups.", "Guaranteed faster execution and complete protection against cache attacks.", " Elimination of all memory accesses during AES encryption.", "A change to AES's underlying encryption algorithm."],
        answer=0, explanation=" Performing the transformations requires more instructions than using T-tables. It avoids the large combined tables, but it does not necessarily eliminate cache leakage if the implementation still uses an S-box lookup table."),
    ("masking", True): dict(q="What is a likely tradeoff when you use Boolean masking for lookup-table accesses?",
        options=["It makes every AES operation faster without requiring additional computation.", "It makes the AES key longer and therefore harder to guess.", "It can make lookup patterns harder to interpret, but generating masks and adapting tables adds computation.", "It guarantees that the attacker can never learn anything from the cache."],
        answer=2, explanation="Boolean masking uses random values to obscure intermediate AES values and adapt lookup tables. This can make the relationship between secret values and observed lookup patterns harder to interpret. However, generating masks and adapting tables adds computational overhead."),
    ("masking", False): dict(q="If lookup-table accesses are performed normally, without masking, what opportunity might this give an attacker?",
        options=["The attacker can automatically read every encrypted message as plaintext.", "The attacker can use cache timing differences to investigate which lookup-table locations were accessed.", "The attacker can make AES skip its AddRoundKey operation.", "The attacker can prevent the processor from using its cache."],
        answer=1, explanation="When lookup-table accesses are performed normally, their locations may depend on secret-related values. Because cache hits and misses take different amounts of time, an attacker may measure timing differences to infer which table locations were accessed. These observations can reveal information, but do not automatically expose the plaintext or the entire secret key."),
    ("hw", True): dict(q="What is a likely advantage of using specialized AES instructions, such as AES-NI or ARM Crypto extensions?",
        options=["They change AES into a stronger encryption algorithm.", "They guarantee protection against every possible attack.", "They allow AES to run without any processor hardware.", "They can execute AES operations efficiently using dedicated hardware, reducing the work required from ordinary software instructions."],
        answer=3, explanation="Specialized instructions such as AES-NI and ARM Crypto extensions allow compatible processors to perform AES operations using dedicated hardware. This can reduce the number of ordinary software instructions needed and improve encryption performance. These instructions can also avoid the classic cache-leakage mechanism associated with secret-dependent software lookup tables, but they do not eliminate every possible vulnerability."),
    ("hw", False): dict(q="What is a likely consequence of implementing AES on a standard processor without dedicated AES instructions?",
        options=["AES cannot be implemented correctly on that processor.", "AES may require more ordinary instructions to perform its operations, increasing the time needed to encrypt messages.", "AES automatically becomes resistant to cache timing attacks.", "AES no longer needs to perform SubBytes, ShiftRows, MixColumns, or AddRoundKey."],
        answer=1, explanation="Without dedicated AES instructions, a general-purpose processor may need to execute multiple ordinary instructions to perform AES operations such as SubBytes and MixColumns. This can increase encryption time compared with hardware-accelerated AES. The processor can still implement AES correctly, and its vulnerability to cache attacks depends on the implementation—for example, whether it uses secret-dependent lookup tables."),
}

# Three separate questions for the final assessment.
ASSESSMENT = [
    dict(q="Why can two systems use the same AES algorithm but have different encryption performance?",
        options=["Each system uses a different mathematical encryption algorithm, even if both are called AES.", "Different implementations can perform AES operations differently, such as using lookup tables, ordinary processor instructions, or specialized AES hardware.", "A system that encrypts messages more slowly must use a longer AES key.", "The AES algorithm automatically changes its number of operations depending on how fast the processor is."],
        answer=1, explanation="AES defines the encryption operations, but implementations can execute those operations in different ways. Lookup tables and specialized processor instructions can improve performance, while computing operations using ordinary instructions may require more work."),
    dict(q="Why can an AES implementation that uses lookup tables be vulnerable to cache timing attacks?",
        options=["Lookup tables store the secret key in plaintext, allowing an attacker to read it directly.", "Lookup tables cause AES to skip some encryption rounds, making the ciphertext easier to decrypt.", "The locations accessed in a lookup table can depend on secret-related values, and those accesses can affect observable cache timing.", "Lookup tables prevent the processor from using its cache efficiently, making all memory accesses slower."],
        answer=2, explanation="The memory locations accessed during AES may depend on intermediate values involving the secret key. Because cache hits and misses take different amounts of time, an attacker may use timing observations to infer information about the lookup patterns and potentially the key."),
    dict(q="How can an attacker use differences between cache hits and cache misses to learn information about an AES computation?",
        options=["By measuring execution times and using timing differences to infer which memory locations were accessed.", "By reading every value stored in the processor's cache without interacting with the system.", "By making cache misses change the mathematical operations performed by AES.", "By forcing AES to encrypt messages without using its secret key."],
        answer=0, explanation="Cache hits are generally faster than cache misses. By measuring timing differences across repeated operations, an attacker may infer memory access patterns and learn information about secret-dependent computations. This does not automatically reveal the entire secret key or plaintext."),
]

# ------------------- game rules --------------------
DECISIONS = ["sbox", "ttable", "masking", "hw"]

# Performance parameters and their sources (for the simulation, not real numbers):
BASE_DELAY = 10          # seconds per message for the slowest implementation, not justified, but has been tested to show that each implementation has a different resulting delay

SBOX_SPEEDUP = 10       # table lookup instead of computing SubBytes 
# (https://scispace.com/pdf/timing-attack-on-a-modified-dynamic-s-box-implementation-of-5dpgjkgbhx.pdf) Found that S-box lookup is 10 times faster than computing SubBytes
TTABLE_SPEEDUP = 0.25     # merged round tables instead of separate steps
# (https://rd.springer.com/content/pdf/10.1007/11552055_2.pdf) Found that best case T-tables decrease cycle count from 1600 to 1200, for 25% speedup
MASKING_OVERHEAD = 9.37   # boolean masking cost
# (https://link.springer.com/content/pdf/10.1007/978-3-540-72738-5_10.pdf) Assuming just masking to S-box lookups, with strong randomization for strongests masking security, best case overhead is increasing from 1637 cycles to 15,332 cycles, for 9.37 times more cycles
HW_SPEEDUP = 0.829          # dedicated AES instructions multiply remaining time
# (https://www.intel.com/content/dam/develop/external/us/en/documents/10tb24-breakthrough-aes-performance-with-intel-aes-new-instructions-final-secure-165683.pdf) showed off AES-NI, which reduced the cycle count to ~1.3 cycles/byte, compared to a baseline (https://eprint.iacr.org/2009/129.pdf) of 7.59 cycles/byte for AES-128, this is a 82.9% speedup

TRACES_SBOX = 2**13*3386       # traces to recover key: S-box only, assuming 1024 Byte tables
# (https://eprint.iacr.org/2005/271.pdf) found that reducing look ups to just S-boxes (no T-tables) with 1024 Byte tables, increased the number of traces needed by 3386 times
TRACES_TTABLE = 2**13       # traces to recover key: T-tables
# (https://www.iacr.org/archive/ches2006/16/16.pdf) in the remote timing attack on AES-128, using collisions within one encryption and targets the final round of encryption, taking worst case, 2^13 traces
MASKING_COMPONENT = 2  # (https://scispace.com/pdf/towards-sound-approaches-to-counteract-power-analysis-2ahx28uuq3.pdf), (https://iacr.org/submit/files/slides/2023/crypto/crypto2023/4/slides.pdf) Masking exponentially increases the noise in leakages, we are simulating a first-order masking which splits values into a mask and a masked value, creating 2 shares for each value. This means that the amount of noise in the system is squared by splitting the values into 2 shares. So we square the number of traces needed for the attack to account for this increase in noise
NO_ATTACK_CAP = 23_726_566   # traces the simulated attacker can gather before the lifetime of the key is over (number of encryptions before the key must be changed) (https://www.ietf.org/archive/id/draft-ietf-tls-rfc8446bis-13.html section 5.5, defines a key lifetime of 2^24.5 records for AES-GCM, which is 23,726,566.4, round down to 23,726,566)

def is_available(decision, choices):
    """T-tables build on S-box tables; masking protects table lookups."""
    if decision in ("ttable", "masking"):
        return choices.get("sbox") is True
    return True

def next_decision(choices):
    for d in DECISIONS:
        if d not in choices and is_available(d, choices):
            return d
    return None

def skipped_decisions(choices):
    return [d for d in DECISIONS if d not in choices and not is_available(d, choices)]

def per_message_delay(choices):
    f = BASE_DELAY
    if choices.get("sbox"):
        f /= SBOX_SPEEDUP
    if choices.get("ttable"):
        f *= (1 - TTABLE_SPEEDUP)
    if choices.get("masking"):
        f *= MASKING_OVERHEAD
    f = max(f, 0.2)
    if choices.get("hw"):
        f *= (1 - HW_SPEEDUP)
    return max(f, 0.1)

def traces_needed(choices):
    """Traces to recover the key, or None if no practical cache attack exists."""
    if choices.get("hw") or not choices.get("sbox"):
        return None
    n = TRACES_TTABLE if choices.get("ttable") else TRACES_SBOX
    return n ** MASKING_COMPONENT if choices.get("masking") else n

def explain_attack(choices, traces):
    if traces is None:
        return "placeholder_attack_explanation_1"
    s = "placeholder_attack_explanation_2 "
    s += ("placeholder_attack_explanation_3"
          if choices.get("masking") else
          "placeholder_attack_explanation_4")
    return s

@dataclass
class GameState:
    choices: dict = field(default_factory=dict)       # decision -> True/False
    predictions: list = field(default_factory=list)   # (decision, was_correct)
    key: bytes = b""
    total_time: float = 0.0
    traces: Optional[int] = None                      # None = no practical attack
    assessment_score: int = 0
    assessment_total: int = 0

# ------------------- aes engine ---------------------
MESSAGES = ["HELLO WORLD", "MEET AT NOON", "SEND MORE CASH", "ATTACK AT DAWN", "PASSWORD IS 1234"]

def make_key(text):
    """Turn whatever the student types into a 16-byte AES key."""
    return text.encode()[:16].ljust(16, b"\0")

def encrypt(key, message):
    return AES.new(key, AES.MODE_ECB).encrypt(pad(message.encode(), 16))

# ------------------- ui helpers ---------------------
WRAP = 780

class Screen(ttk.Frame):
    def __init__(self, app, title):
        super().__init__(app, padding=20)
        self.app = app
        self.game = app.game          # NOTE: not "state": Tk already has a .state() method
        ttk.Label(self, text=title, style="Title.TLabel").pack(anchor="w", pady=(0, 12))
        #From line 189 to 203 and 207 to 224 added by copilot to make it scrollable.
        self.body_area = ttk.Frame(self)
        self.body_area.pack(fill="both", expand=True)
        self.body_area.columnconfigure(0, weight=1)
        self.body_area.rowconfigure(0, weight=1)
        self.body_canvas = tk.Canvas(self.body_area, borderwidth=0, highlightthickness=0)
        self.body_canvas.grid(row=0, column=0, sticky="nsew")
        self.body_scrollbar = ttk.Scrollbar(self.body_area, orient="vertical",
                                            command=self.body_canvas.yview)
        self.body_scrollbar.grid(row=0, column=1, sticky="ns")
        self.body_canvas.configure(yscrollcommand=self.body_scrollbar.set)
        self.body = ttk.Frame(self.body_canvas)
        self.body_window = self.body_canvas.create_window((0, 0), window=self.body, anchor="nw")
        self.body.bind("<Configure>", self._update_scroll_region)
        self.body_canvas.bind("<Configure>", self._resize_body)
        self.bind_all("<MouseWheel>", self._scroll_body)
        self.footer = ttk.Frame(self)
        self.footer.pack(fill="x", pady=(12, 0))

    def _update_scroll_region(self, _event=None):
        self.body_canvas.configure(scrollregion=self.body_canvas.bbox("all"))

    def _resize_body(self, event):
        self.body_canvas.itemconfigure(self.body_window, width=event.width)

    def _scroll_body(self, event):
        widget = event.widget
        while widget is not None:
            if widget == self.body:
                self.body_canvas.yview_scroll(-int(event.delta / 120), "units")
                break
            widget = getattr(widget, "master", None)

    def destroy(self):
        self.unbind_all("<MouseWheel>")
        super().destroy()

    def add_button(self, text, command, disabled=False):
        b = ttk.Button(self.footer, text=text, command=command)
        b.pack(side="right", padx=4)
        if disabled:
            b.state(["disabled"])
        return b

    def label(self, parent, text, **kw):
        kw.setdefault("wraplength", WRAP)
        kw.setdefault("justify", "left")
        return ttk.Label(parent, text=text, **kw)

class QuizFrame(ttk.Frame):
    """One multiple-choice question at a time with immediate feedback.
    questions: list of dict(q, options, answer, explanation, tag=None)
    on_done(results): results is a list of (tag, was_correct)."""

    def __init__(self, parent, questions, on_done):
        super().__init__(parent)
        self.questions, self.on_done = questions, on_done
        self.i, self.results = 0, []
        self.var = tk.IntVar(value=-1)
        self.counter = ttk.Label(self, style="Sub.TLabel")
        self.counter.pack(anchor="w")
        self.qlabel = ttk.Label(self, wraplength=WRAP, justify="left", style="Q.TLabel")
        self.qlabel.pack(anchor="w", pady=(4, 10))
        self.opts = ttk.Frame(self)
        self.opts.pack(fill="x")
        self.feedback = ttk.Label(self, wraplength=WRAP, justify="left")
        self.feedback.pack(anchor="w", pady=10)
        self.btn = ttk.Button(self)
        self.btn.pack(anchor="e")
        self.show()

    def show(self):
        q = self.questions[self.i]
        self.counter.config(text=f"Question {self.i + 1} of {len(self.questions)}")
        self.qlabel.config(text=q["q"])
        for w in self.opts.winfo_children():
            w.destroy()
        self.var.set(-1)
        self.radios = []
        for idx, text in enumerate(q["options"]):
            r = tk.Radiobutton(self.opts, text=f"{chr(65 + idx)}. {text}", variable=self.var, value=idx,
                               anchor="w", justify="left", wraplength=WRAP - 30, padx=6, pady=3)
            r.pack(fill="x", anchor="w")
            self.radios.append(r)
        self.feedback.config(text="")
        self.btn.config(text="Submit", command=self.submit)

    def submit(self):
        choice = self.var.get()
        if choice < 0:
            self.feedback.config(text="Pick an answer first.", foreground="gray30")
            return
        q = self.questions[self.i]
        ok = choice == q["answer"]
        self.results.append((q.get("tag"), ok))
        for idx, r in enumerate(self.radios):
            r.config(state="disabled")
            base = f"{chr(65 + idx)}. {q['options'][idx]}"
            if idx == q["answer"]:
                r.config(text="\u2713 " + base, disabledforeground="#1a7f37")
            elif idx == choice:
                r.config(text="\u2717 " + base, disabledforeground="#c62828")
        head = "Correct! " if ok else f"Not quite. The correct answer is {chr(65 + q['answer'])}. "
        self.feedback.config(text=head + q["explanation"], foreground="#1a7f37" if ok else "#c62828")
        last = self.i == len(self.questions) - 1
        self.btn.config(text="Finish" if last else "Next question", command=self.advance)

    def advance(self):
        self.i += 1
        if self.i >= len(self.questions):
            self.on_done(self.results)
        else:
            self.show()

# ------------------- ui screens -------------------
class IntroScreen(Screen):
    def __init__(self, app):
        super().__init__(app, "Welcome to the AES Implementation Lab")
        self.i = 0
        self.title_lbl = ttk.Label(self.body, style="Q.TLabel")
        self.title_lbl.pack(anchor="w", pady=(10, 8))
        self.text_lbl = self.label(self.body, "", font=("Helvetica", 13))
        self.text_lbl.pack(anchor="w")
        aes_image_path = Path(__file__).parent / "assets" / "aes_rounds_flowchart.png"
        cache_image_path = Path(__file__).parent / "assets" / "cache_state.png"
        key_image_path = Path(__file__).parent / "assets" / "key_recovery.png"
        self.aes_image = tk.PhotoImage(file=aes_image_path).subsample(2, 2)
        self.aes_image_lbl = ttk.Label(self.body, image=self.aes_image)
        self.cache_image = tk.PhotoImage(file=cache_image_path).subsample(2, 2)
        self.cache_image_lbl = ttk.Label(self.body, image=self.cache_image)
        self.key_image = tk.PhotoImage(file=key_image_path).subsample(2, 2)
        self.key_image_lbl = ttk.Label(self.body, image=self.key_image)
        self.next_btn = self.add_button("Next", self.next)
        self.back_btn = self.add_button("Back", self.back)
        self.refresh()

    def refresh(self):
        t, *body = INTRO[self.i]
        self.title_lbl.config(text=f"{self.i + 1}/{len(INTRO)}  {t}")
        self.text_lbl.config(text="\n\n".join(body))
        match(self.i):
            case 1:
                self.aes_image_lbl.pack(anchor="w", pady=(12, 0))
            case 2:
                try:
                    self.aes_image_lbl.pack_forget()
                except:
                    print("No aes image to forget")
                self.cache_image_lbl.pack(anchor="w", pady=(12, 0))
                self.key_image_lbl.pack(anchor="w", pady=(12, 0))
            case _:
                self.aes_image_lbl.pack_forget()
                self.cache_image_lbl.pack_forget()
                self.key_image_lbl.pack_forget()
        self.back_btn.state(["!disabled"] if self.i else ["disabled"])
        self.next_btn.config(text="Start designing" if self.i == len(INTRO) - 1 else "Next")

    def next(self):
        if self.i == len(INTRO) - 1:
            self.app.next_screen()
        else:
            self.i += 1
            self.refresh()

    def back(self):
        self.i -= 1
        self.refresh()

class DesignScreen(Screen):
    def __init__(self, app):
        super().__init__(app, "Design your AES implementation")
        self.status = self.label(self, "", style="Sub.TLabel")
        self.status.pack(anchor="w", before=self.footer)
        self.show_next()

    def show_next(self):
        for w in self.body.winfo_children():
            w.destroy()
        ch = self.game.choices
        d = next_decision(ch)
        if d is None:
            self.app.next_screen()
            return
        info = DECISION_INFO[d]
        ttk.Label(self.body, text=info["title"], style="Q.TLabel").pack(anchor="w")
        self.label(self.body, info["prompt"]).pack(anchor="w", pady=(0, 10))
        for value in (True, False):
            name, desc = info[value]
            box = ttk.LabelFrame(self.body, text=name, padding=10)
            box.pack(fill="x", pady=6)
            self.label(box, desc, wraplength=640).pack(side="left", anchor="w")
            ttk.Button(box, text="Choose", command=lambda v=value, dd=d: self.choose(dd, v)).pack(side="right")
        picked = [DECISION_INFO[k][v][0] for k, v in ch.items()]
        skipped = [DECISION_INFO[k]["title"].split(": ")[1] for k in skipped_decisions(ch)]
        text = "Your choices so far: " + (", ".join(picked) if picked else "none")
        if skipped:
            text += f"\nSkipped (not compatible with earlier choices): {', '.join(skipped)}"
        self.status.config(text=text)

    def choose(self, d, value):
        self.game.choices[d] = value
        self.show_next()

class PredictScreen(Screen):
    def __init__(self, app):
        super().__init__(app, "Predict the impact of your choices")
        made = [d for d in DECISIONS if d in self.game.choices]
        qs = []
        for d in made:
            q = PREDICTION_QUESTIONS[(d, self.game.choices[d])].copy()
            q["tag"] = d
            qs.append(q)
        QuizFrame(self.body, qs, self.done).pack(fill="both", expand=True)

    def done(self, results):
        self.game.predictions = results
        self.app.next_screen()

class PerformanceScreen(Screen):
    TICK_MS = 100

    def __init__(self, app):
        super().__init__(app, "Performance test")
        self.label(self.body, "Enter a secret key, then watch your AES system encrypt each message "
                              "(AES-ECB). Encryption time depends on your design choices.").pack(anchor="w")
        row = ttk.Frame(self.body)
        row.pack(anchor="w", pady=8)
        ttk.Label(row, text="Secret key:").pack(side="left")
        self.entry = ttk.Entry(row, width=24)
        self.entry.pack(side="left", padx=6)
        self.start_btn = ttk.Button(row, text="Start test", command=self.start)
        self.start_btn.pack(side="left")
        self.note = ttk.Label(row, text="", foreground="#c62828")
        self.note.pack(side="left", padx=8)

        cols = ttk.Frame(self.body)
        cols.pack(fill="both", expand=True, pady=10)
        self.left = ttk.LabelFrame(cols, text="Plaintext messages", padding=8)
        self.left.pack(side="left", fill="both", expand=True)
        mid = ttk.Frame(cols)
        mid.pack(side="left", padx=12)
        self.canvas = tk.Canvas(mid, width=190, height=150, bg="black", highlightthickness=0)
        self.canvas.pack()
        self.box_text = self.canvas.create_text(95, 75, text="Your AES system", fill="white",
                                                font=("Helvetica", 12, "bold"), width=170)
        self.bar = ttk.Progressbar(mid, length=190, maximum=100)
        self.bar.pack(pady=6)
        self.right = ttk.LabelFrame(cols, text="Ciphertext (hex)", padding=8)
        self.right.pack(side="left", fill="both", expand=True)
        self.result = ttk.Label(self.body, text="", style="Q.TLabel")
        self.result.pack(anchor="w")
        self.next_btn = self.add_button("Run cache attack", self.app.next_screen, disabled=True)

    def start(self):
        text = self.entry.get().strip()
        if not text:
            self.note.config(text="Please enter a key.")
            return
        self.note.config(text="")
        self.game.key = make_key(text)
        self.game.total_time = 0.0
        self.delay = per_message_delay(self.game.choices)
        self.idx = 0
        self.entry.state(["disabled"])
        self.start_btn.state(["disabled"])
        self.after(600, self.begin_message)

    def begin_message(self):
        if self.idx >= len(MESSAGES):
            self.result.config(text=f"Total encryption time: {self.game.total_time:.1f} s")
            self.canvas.itemconfig(self.box_text, text="Done")
            self.next_btn.state(["!disabled"])
            return
        ttk.Label(self.left, text=MESSAGES[self.idx], font=("Courier", 11)).pack(anchor="w", pady=2)
        self.canvas.itemconfig(self.box_text, text="Encrypting...")
        self.elapsed = 0.0
        self.tick()

    def tick(self):
        self.elapsed += self.TICK_MS / 1000
        self.bar["value"] = min(100, self.elapsed / self.delay * 100)
        if self.elapsed >= self.delay:
            self.finish_message()
        else:
            self.after(self.TICK_MS, self.tick)

    def finish_message(self):
        ct = encrypt(self.game.key, MESSAGES[self.idx]).hex()
        ttk.Label(self.right, text=f"{ct[:16]}\u2026{ct[-8:]}", font=("Courier", 11)).pack(anchor="w", pady=2)
        self.game.total_time += self.delay
        self.idx += 1
        self.bar["value"] = 0
        self.canvas.itemconfig(self.box_text, text="Your AES system")
        self.after(1000, self.begin_message)

class AttackScreen(Screen):
    STEPS = 40
    def __init__(self, app):
        super().__init__(app, "Simulated cache timing attack")
        self.traces = traces_needed(self.game.choices)
        self.game.traces = self.traces
        self.label(self.body, "placeholder_attack_description_1").pack(anchor="w")
        self.counter = ttk.Label(self.body, text="Traces collected: 0", style="Q.TLabel")
        self.counter.pack(anchor="w", pady=(14, 4))
        self.bar = ttk.Progressbar(self.body, length=500, maximum=self.STEPS)
        self.bar.pack(anchor="w")
        self.outcome = self.label(self.body, "", font=("Helvetica", 13, "bold"))
        self.outcome.pack(anchor="w", pady=14)
        self.why = self.label(self.body, "")
        self.why.pack(anchor="w")
        self.next_btn = self.add_button("See results", self.app.next_screen, disabled=True)
        self.step = 0
        self.after(500, self.run)

    def run(self):
        self.step += 1
        target = self.traces or NO_ATTACK_CAP
        self.bar["value"] = self.step
        self.counter.config(text=f"Traces collected: {int(target * self.step / self.STEPS):,}")
        if self.step < self.STEPS:
            self.after(60, self.run)
        else:
            self.conclude()

    def conclude(self):
        if self.traces is None:
            self.outcome.config(text=f"Attack failed: key NOT recovered after {NO_ATTACK_CAP:,} traces.",
                                foreground="#1a7f37")
        else:
            self.outcome.config(text=f"Key recovered after {self.traces:,} traces: {self.game.key.hex()}",
                                foreground="#c62828")
        self.why.config(text=explain_attack(self.game.choices, self.traces))
        self.next_btn.state(["!disabled"])

class ResultsScreen(Screen):
    def __init__(self, app):
        super().__init__(app, "Your results")
        g = self.game
        box = ttk.LabelFrame(self.body, text="Your implementation choices", padding=10)
        box.pack(fill="x")
        for d in DECISIONS:
            if d in g.choices:
                v = g.choices[d]
                perf, sec = EFFECTS[(d, v)]
                ttk.Label(box, text=DECISION_INFO[d][v][0], font=("Helvetica", 12, "bold")).pack(anchor="w", pady=(6, 0))
                self.label(box, f"Performance: {perf}\nCache security: {sec}").pack(anchor="w", padx=14)
            else:
                name = DECISION_INFO[d]["title"].split(": ")[1]
                self.label(box, f"{name}: skipped (not applicable to your design)",
                           style="Sub.TLabel").pack(anchor="w", pady=(6, 0))
        correct = sum(ok for _, ok in g.predictions)
        total = ttk.LabelFrame(self.body, text="Overall", padding=10)
        total.pack(fill="x", pady=12)
        t = "no practical attack found" if g.traces is None else f"{g.traces:,} traces to recover the key"
        self.label(total, f"Total encryption time: {g.total_time:.1f} s\n"
                          f"Cache timing attack: {t}\n"
                          f"Prediction questions correct: {correct} of {len(g.predictions)}",
                   font=("Helvetica", 12)).pack(anchor="w")
        self.label(self.body, "placeholder_results_summary_1", style="Sub.TLabel").pack(anchor="w")
        self.add_button("Final assessment", self.app.next_screen)

class AssessmentScreen(Screen):
    def __init__(self, app):
        super().__init__(app, "Final assessment")
        self.quiz = QuizFrame(self.body, ASSESSMENT, self.done)
        self.quiz.pack(fill="both", expand=True)

    def done(self, results):
        score, total = sum(ok for _, ok in results), len(results)
        self.game.assessment_score, self.game.assessment_total = score, total
        self.quiz.destroy()
        ttk.Label(self.body, text=f"You scored {score} / {total}", style="Q.TLabel").pack(anchor="w", pady=20)
        self.label(self.body, "placeholder_closing_message_1").pack(anchor="w")
        self.add_button("Quit", self.app.destroy)
        self.add_button("Play again", self.app.restart)

#  -------------------- app --------------------
class App(tk.Tk):
    FLOW = [IntroScreen, DesignScreen, PredictScreen, PerformanceScreen, AttackScreen,
            ResultsScreen, AssessmentScreen]

    def __init__(self):
        super().__init__()
        self.title("AES Implementation Lab")
        self.geometry("900x700")
        self.minsize(820, 620)
        style = ttk.Style(self)
        style.configure("Title.TLabel", font=("Helvetica", 18, "bold"))
        style.configure("Q.TLabel", font=("Helvetica", 13, "bold"))
        style.configure("Sub.TLabel", foreground="gray40")
        self.game = GameState()
        self.index, self.current = -1, None
        self.next_screen()

    def next_screen(self):
        if self.current is not None:
            self.current.destroy()
        self.index += 1
        self.current = self.FLOW[self.index](self)
        self.current.pack(fill="both", expand=True)

    def restart(self):
        self.game = GameState()
        self.index = -1
        self.next_screen()

if __name__ == "__main__":
    App().mainloop()