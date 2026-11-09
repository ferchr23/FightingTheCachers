"""

Fighting the Cacherssssssssssssssss woooooo
Run with:  python main.py

1) content  2) game rules  3) aes engine  4) ui helpers  5) screens  6) app

"""
import tkinter as tk
import tkinter.font as tkfont
from dataclasses import dataclass, field
from pathlib import Path #added by copilot to make it scrollable
from tkinter import ttk
from typing import Optional
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

ASSETS = Path(__file__).parent / "assets"

# ------------------- content -------------------
# Each intro slide is a list of blocks:
#   ("h", heading)  ("p", paragraph)  ("ul", [bullet, ...])  ("img", filename, subsample)
INTRO = [
    [
        ("h", "Welcome to Fighting the Cachers!"),
        ("p", "On their own, encryption schemes like AES are nothing more than theoretical algorithms. To encrypt electronic messages, they must be implemented, either in software or in hardware. In this game, your goal is to implement the AES encryption algorithm in a way that is both performant and secure against cache timing leakages."),
        ("h", "What is AES?"),
        ("p", "AES, or the Advanced Encryption Standard, is the National Institute of Standards and Technology’s symmetric-key encryption algorithm of choice for encrypting electronic data. AES is used by two parties who share a single secret key to encrypt and decrypt messages. AES takes blocks of data and encrypts them with the secret key. It uses confusion to obscure the relationship between the key/message and the resulting ciphertext, and diffusion to spread the influence of the message across the ciphertext."),
    ],
    [
        ("h", "What does AES do?"),
        ("p", "As an algorithm, AES has four major steps:"),
        ("ul", ["SubBytes: a nonlinear substitution function",
                "ShiftRows: a rearranging of the message bytes",
                "MixColumns: a linear matrix multiplication",
                "AddRoundKey: the application of the secret key"]),
        ("p", "These four steps make up a “round” of AES, and many rounds are performed in series to encrypt a single block of the message. The number of rounds depends on the length of your secret key. For example, AES-128 uses a 128-bit secret key and has 10 rounds, while AES-256 uses a 256-bit secret key and has 14 rounds."),
        ("p", "The AES algorithm is defined by these four steps and the way they come together in a series of rounds. Every implementation of AES, whether in software or in hardware, performs these steps. How it performs them is where implementations come into their own."),
        ("img", "aes_rounds_flowchart.png", 2),
    ],
    [
        ("h", "What is the performance of an AES implementation?"),
        ("p", "When we discuss the performance of an AES implementation here, we are referring to the time required to encrypt messages. Implementations with higher performance compute the steps of AES faster than those with lower performance."),
        ("h", "What are cache timing leakages?"),
        ("p", "To speed up reading data from memory, computers make use of caches. Caches temporarily store data that has been accessed recently, so that if the data is needed again, the processor can read it from the cache instead of from a slower memory component. If the required data is found in the cache, it is called a “cache hit”; if it is not, it is called a “cache miss.” By nature, cache hits are faster memory accesses than cache misses."),
        ("img", "cache_state.png", 1),
        ("p", "Adversaries attacking a computer system can use cache hits and cache misses to learn what data has been stored in the cache recently. They can record the time required to run a program, such as AES, to determine whether a cache hit or a cache miss occurred. These “cache timing leakages” can allow an adversary to learn the access patterns of lookup tables."),
        ("img", "key_recovery.png", 1),
    ],
    [
        ("h", "The role of lookup tables"),
        ("p", "In AES, lookup tables are often used to speed up computation, which increases the risk of cache timing leakages. The amount of information revealed through cache timing leakages can be reduced, but this often comes with a tradeoff and depends entirely on how AES has been implemented."),
        ("p", "Your task now is to investigate those tradeoffs by designing an AES implementation that is both performant and resistant to cache timing leakages."),
    ],
]

DECISION_INFO = {
    "sbox": {
        "title": "Decision 1: 'Sub' me in coach!",
        "name": "SubBytes method",
        "prompt": "Determine how your system handles the SubBytes operation. Choose carefully...",
        True: ("Use S-boxes for SubBytes", "Precompute the nonlinear substitutions applied in SubBytes when setting up AES. The substitutions are stored as a lookup table in memory. This lookup table, called an S-box, is 256 bytes in size and can fit into 4 lines of the cache. Which value is accessed in the S-box depends on the input value, which is a combination of the secret round key with either the plaintext message or the output of a previous round."),
        False: ("Compute SubBytes Manually", "The substitutions applied in SubBytes can be computed numerically as an inversion in a Galois Field. Compared to the simpler computations in ShiftRows, MixColumns, and AddRoundKey, the inversion over a Galois Field is the most complicated part of an AES round."),
    },
    "ttable": {
        "title": "Decision 2: To T or not to T...",
        "name": "T-tables",
        "prompt": "Will you choose to use T-tables or stick with the traditional route?",
        True: ("Use T-tables for Each Round", "Similar to how S-boxes precompute the substitutions in SubBytes, T-tables precompute most of an entire round of AES. SubBytes, ShiftRows, and MixColumns are replaced with a memory table lookup, leaving only AddRoundKey to be performed in real time. Just as with S-boxes, the accessed value of the T-table lookup depends on the round key and either the plaintext message or the output of the previous round. To include the computation of ShiftRows and MixColumns, each T-table is 4 times the size of an S-box. This means each one takes up 16 cache lines instead of an S-box’s 4 lines."),
        False: ("Perform Rounds Normally", "Perform the computations for ShiftRows and MixColumns on the fly in each round. ShiftRows is a simple reordering of bytes, and MixColumns is a matrix multiplication with a fixed array."),
    },
    "masking": {
        "title": "Decision 3: Mask off, hold up Mask on?",
        "name": "Masking",
        "prompt": "Is masking what you need, or is it better to keep things the same? You decide.",
        True: ("Use Boolean Masking for Memory Accesses", "Boolean masking was originally created as a power-analysis countermeasure. Every intermediate value in AES is XORed with a random mask. All lookup tables are recomputed based on the mask, so any single lookup is uniformly random. This does not necessarily prevent cache attacks, but it does obscure the absolute index of lookups. Applying a mask requires pseudorandom values to be generated and each lookup table to be recomputed, which adds computation. Masks can be reused for multiple lookups to reduce this computation; however, the lookups are then no longer uniformly random."),
        False: ("Perform Memory Accesses as Usual", "All accesses to data in the cache are performed normally, with no masking."),
    },
    "hw": {
        "title": "Decision 4: Chip decisions (and we're not talking Doritos vs. Lay's)",
        "name": "Processor",
        "prompt": "They finally released that fancy new chip. I hope your computer can handle it...",
        True: ("Use a Special Instruction Chip", "Use a specialized chip that has been designed to execute AES efficiently. Examples include Intel's AES-NI and ARM's Crypto extensions, each of which provides dedicated instructions to execute AES round operations efficiently. Each of the round operations is implemented directly in hardware rather than with general-purpose arithmetic logic and instructions."),
        False: ("Use a Standard Processor", "Use a general-purpose processor to run your AES implementation. Some operations required in AES, like XOR, shifting, and data movement, are handled by existing logic and instructions. Other operations, like the Galois Field arithmetic of SubBytes and MixColumns, are not commonly supported by ALUs and must be implemented as a combination of smaller instructions. Using more instructions generally increases the runtime of a program."),
    },
}

# (decision, value) -> (performance effect, cache-security effect) for the results screen
EFFECTS = {
    ("sbox", True): ("Speeds up performance by replacing computation with faster lookups.", "Using lookup tables opens up the possibility of cache timing leakages."),
    ("sbox", False): ("Computing SubBytes in real time is slower than S-box lookups.", "Avoiding lookup tables prevents the most common source of cache timing leakages."),
    ("ttable", True): ("Speeds up performance by combining multiple steps of computation into one lookup.", "Greatly increases the amount of information leaked in cache timing attacks."),
    ("ttable", False): ("Performing SubBytes, ShiftRows, and MixColumns separately is slower than one lookup.", "Prevents more information from being leaked than with S-boxes alone."),
    ("masking", True): ("Generating pseudorandom masks and recomputing tables adds significant computation time.", "First-order Boolean masking increases the leakage noise exponentially (by a power of 2), improving security."),
    ("masking", False): ("Applying no mask keeps computation the same.", "Applying no mask keeps security the same."),
    ("hw", True): ("Specialized chips execute AES computation more efficiently, speeding up encryption.", "Specialized chips have minimal impact on cache timing attack security."),
    ("hw", False): ("Standard processors generally use more instructions and have a longer runtime.", "Using a standard processor has minimal impact on cache timing attack security."),
}

# Each question: dict(q=text, options=[...], answer=index of correct option, explanation=text)
# Prediction phase: one question per decision the student made, selected by the decision and the player's choice.
PREDICTION_QUESTIONS = {
    ("sbox", True): dict(q="Implementing SubBytes with S-box lookup tables will most likely…",
        options=["Improve performance, but potentially expose secret-dependent memory accesses to cache attacks.", "Reduce performance and automatically prevent cache attacks.", "Improve performance and eliminate all implementation-level vulnerabilities.", "Change the mathematical operations that define AES."],
        answer=0, explanation="Lookup tables can speed up SubBytes, but the accessed location can depend on secret-related intermediate values. Cache observations may reveal information about those accesses."),
    ("sbox", False): dict(q="If you compute the SubBytes transformation mathematically instead of using an S-box lookup table, what is the most likely tradeoff?",
        options=["Higher performance, because all mathematical operations are faster than memory accesses.", "Potentially more computation, but less reliance on secret-dependent table accesses.", "No change in performance or cache behavior, because AES is unchanged.", "Guaranteed immunity to every cache attack, regardless of how the computation is implemented."],
        answer=1, explanation="Computing the finite-field transformation can require more instructions than a table lookup. It can avoid the particular leakage mechanism caused by secret-dependent table accesses, provided the computation itself is implemented appropriately. Arithmetic alone does not guarantee constant-time execution."),
    ("ttable", True): dict(q="Compared with an S-box lookup implementation, using T-tables to combine several AES round operations will most likely…",
        options=["Require fewer table lookups, use less cache space, and eliminate cache leakage.", "Replace the entire AES algorithm with a different encryption algorithm.", "Potentially speed up round processing, but use larger tables and expose more cache locations to secret-dependent accesses.", "Make AES slower while guaranteeing that every memory access is independent of the secret key."],
        answer=2, explanation="T-tables combine work from multiple AES transformations, potentially reducing instruction overhead. However, they occupy more cache space than S-box tables and still use secret-dependent lookups, which can create cache leakage."),
    ("ttable", False): dict(q="If you perform ShiftRows and MixColumns as separate operations instead of combining them into T-tables, what should you expect?",
        options=["More explicit computation, but less reliance on large T-table lookups.", "Guaranteed faster execution and complete protection against cache attacks.", "Elimination of all memory accesses during AES encryption.", "A change to AES's underlying encryption algorithm."],
        answer=0, explanation="Performing the transformations separately requires more instructions than using T-tables. It avoids the large combined tables, but it does not necessarily eliminate cache leakage if the implementation still uses an S-box lookup table."),
    ("masking", True): dict(q="What is a likely tradeoff when you use Boolean masking for lookup-table accesses?",
        options=["It makes every AES operation faster without requiring additional computation.", "It makes the AES key longer and therefore harder to guess.", "It can make lookup patterns harder to interpret, but generating masks and adapting tables adds computation.", "It guarantees that the attacker can never learn anything from the cache."],
        answer=2, explanation="Boolean masking uses random values to obscure intermediate AES values and adapt lookup tables. This can make the relationship between secret values and observed lookup patterns harder to interpret. However, generating masks and adapting tables adds computational overhead."),
    ("masking", False): dict(q="If lookup-table accesses are performed normally, without masking, what opportunity might this give an attacker?",
        options=["The attacker can automatically read every encrypted message as plaintext.", "The attacker can use cache timing differences to investigate which lookup-table locations were accessed.", "The attacker can make AES skip its AddRoundKey operation.", "The attacker can prevent the processor from using its cache."],
        answer=1, explanation="When lookup-table accesses are performed normally, their locations may depend on secret-related values. Because cache hits and misses take different amounts of time, an attacker may measure timing differences to infer which table locations were accessed. These observations can reveal information, but they do not automatically expose the plaintext or the entire secret key."),
    ("hw", True): dict(q="What is a likely advantage of using specialized AES instructions, such as AES-NI or ARM Crypto extensions?",
        options=["They change AES into a stronger encryption algorithm.", "They guarantee protection against every possible attack.", "They allow AES to run without any processor hardware.", "They can execute AES operations efficiently using dedicated hardware, reducing the work required from ordinary software instructions."],
        answer=3, explanation="Specialized instructions such as AES-NI and ARM Crypto extensions allow compatible processors to perform AES operations using dedicated hardware. This can reduce the number of ordinary software instructions needed and improve encryption performance. These instructions can also avoid the classic cache-leakage mechanism associated with secret-dependent software lookup tables, but they do not eliminate every possible vulnerability."),
    ("hw", False): dict(q="What is a likely consequence of implementing AES on a standard processor without dedicated AES instructions?",
        options=["AES cannot be implemented correctly on that processor.", "AES may require more ordinary instructions to perform its operations, increasing the time needed to encrypt messages.", "AES automatically becomes resistant to cache timing attacks.", "AES no longer needs to perform SubBytes, ShiftRows, MixColumns, or AddRoundKey."],
        answer=1, explanation="Without dedicated AES instructions, a general-purpose processor may need to execute multiple ordinary instructions to perform AES operations such as SubBytes and MixColumns. This can increase encryption time compared with hardware-accelerated AES. The processor can still implement AES correctly, and its vulnerability to cache attacks depends on the implementation, for example, whether it uses secret-dependent lookup tables."),
}

# Final assessment: every prediction question, followed by three general questions.
ASSESSMENT = list(PREDICTION_QUESTIONS.values()) + [
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
    """T-tables build on S-box tables; masking protects table lookups. Specialized Hardware really needs computation to be done, not T-tables."""
    if decision in ("ttable", "masking"):
        return choices.get("sbox") is True
    if decision == "hw":
        return choices.get("ttable") is not True
    return True

def next_decision(choices):
    for d in DECISIONS:
        if d not in choices and is_available(d, choices):
            return d
    return None

def skipped_decisions(choices):
    """Decisions already passed over because they conflict with earlier choices."""
    nxt = next_decision(choices)
    upto = DECISIONS.index(nxt) if nxt else len(DECISIONS)
    return [d for d in DECISIONS[:upto] if d not in choices and not is_available(d, choices)]

def per_message_delay(choices):
    """Set the length of per message encryption delay to simulate processing time for each design option."""
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
        return "By performing SubBytes calculations in real time or in specialized hardware, you avoided using secret-dependent table accesses. Your AES implementation may not be completely immune to cache timing leakage attacks, but it is secure against the most effective and well-known attack methods. The attacker cannot gain enough information to recover the secret key within 2^24.5 (~23,726,566) encryptions, the standard lifetime of an AES key set by TLS version 1.3. Your implementation is secure!"
    if choices.get("ttable") and not choices.get("masking"):
        return "By performing SubBytes, ShiftRows, and MixColumns together as T-tables, you created an implementation that is known to be vulnerable to cache timing attacks. The larger T-tables fill a larger number of cache lines than S-boxes do, so the attacker is more likely to learn information from each message encryption. Targeting the final round of encryption, the worst-case attack on T-table implementations, which watches for collisions within rounds of encryption, can recover the key within 2^13 (8,192) encryptions. This is well within 2^24.5 (~23,726,566) encryptions, the standard lifetime of an AES key set by TLS version 1.3. Consider incorporating masking to increase leakage noise, or move away from T-tables. Your implementation is not secure!"
    if choices.get("ttable") and choices.get("masking"):
        return "Traditionally, performing SubBytes, ShiftRows, and MixColumns together as T-tables creates an implementation that is known to be vulnerable to cache timing attacks. The larger T-tables fill a larger number of cache lines than S-boxes do, so the attacker is more likely to learn information from each message encryption. Targeting the final round of encryption, the worst-case attack on T-table implementations, which watches for collisions within rounds of encryption, can recover the key within 2^13 (8,192) encryptions. However, first-order Boolean masking splits each value into 2 shares: a mask and a masked value. As a result, the leakage noise of the system increases exponentially (by a power of 2). We model this as increasing the number of encryptions needed from 8,192 to 8,192^2 (67,108,864). This is on a similar order to 2^24.5 (~23,726,566) encryptions, the standard lifetime of an AES key set by TLS version 1.3. While the entire key was not recovered, significant information was leaked. Your implementation is partially secure!"
    if choices.get("sbox") and not choices.get("masking"):
        return "By performing SubBytes with precomputed S-boxes, you created an implementation that is partially vulnerable to cache timing attacks. It is more resistant to cache timing leakages than using T-tables, as 1024-byte S-boxes have been shown to increase the number of traces an attacker needs to recover the secret key by a factor of 3,386. This means the attacker needs 8,192 × 3,386 traces, or 27,738,112 encryptions. This is slightly greater than 2^24.5 (~23,726,566) encryptions, the standard lifetime of an AES key set by TLS version 1.3. However, this does not guarantee a secure system, as significant information can still be leaked within the lifetime of the key. Your implementation is partially secure!"
    if choices.get("sbox") and choices.get("masking"):
        return "Traditionally, performing SubBytes with precomputed S-boxes creates an implementation that is partially vulnerable to cache timing attacks. It is more resistant to cache timing leakages than using T-tables, as 1024-byte S-boxes have been shown to increase the number of traces an attacker needs to recover the secret key by a factor of 3,386. This means the attacker needs 8,192 × 3,386 traces, or 27,738,112 encryptions. However, first-order Boolean masking splits each value into 2 shares: a mask and a masked value. As a result, the leakage noise of the system increases exponentially (by a power of 2). We model this as increasing the number of encryptions needed from 27,738,112 to 27,738,112^2 (769,402,857,324,544). This is significantly greater than 2^24.5 (~23,726,566) encryptions, the standard lifetime of an AES key set by TLS version 1.3, so the attacker cannot gain enough information to recover the secret key. Your implementation is secure!"
    return "Unknown outcome"

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
WRAP = 780            # starting wrap width; labels re-wrap to the window width once laid out
GREEN, RED = "#1a7f37", "#c62828"

def autowrap(widget, margin=0):
    """Re-wrap a label's text whenever its width changes. Pack/grid it so it fills horizontally."""
    widget.bind("<Configure>", lambda e: widget.configure(wraplength=max(e.width - margin, 100)), add="+")
    return widget

class Screen(ttk.Frame):
    def __init__(self, app, title):
        super().__init__(app, padding=(24, 16, 24, 12))
        self.app = app
        self.game = app.game          # NOTE: not "state": Tk already has a .state() method
        ttk.Label(self, text=title, style="Title.TLabel").pack(pady=(0, 8))
        ttk.Separator(self).pack(fill="x", pady=(0, 12))
        # Footer is packed before the body so it always stays visible at the bottom.
        self.footer = ttk.Frame(self)
        self.footer.pack(side="bottom", fill="x", pady=(10, 0))
        ttk.Separator(self).pack(side="bottom", fill="x")
        ttk.Label(self.footer, text=f"Step {app.index + 1} of {len(app.FLOW)}",
                  style="Sub.TLabel").pack(side="left")
        #From here to _scroll_body added by copilot to make it scrollable.
        self.body_area = ttk.Frame(self)
        self.body_area.pack(fill="both", expand=True)
        self.body_area.columnconfigure(0, weight=1)
        self.body_area.rowconfigure(0, weight=1)
        self.body_canvas = tk.Canvas(self.body_area, borderwidth=0, highlightthickness=0,
                                     background=ttk.Style(self).lookup("TFrame", "background"))
        self.body_canvas.grid(row=0, column=0, sticky="nsew")
        self.body_scrollbar = ttk.Scrollbar(self.body_area, orient="vertical",
                                            command=self.body_canvas.yview)
        self.body_scrollbar.grid(row=0, column=1, sticky="ns")
        self.body_canvas.configure(yscrollcommand=self.body_scrollbar.set)
        self.body = ttk.Frame(self.body_canvas, padding=(4, 0, 16, 8))
        self.body_window = self.body_canvas.create_window((0, 0), window=self.body, anchor="nw")
        self.body.bind("<Configure>", self._update_scroll_region)
        self.body_canvas.bind("<Configure>", self._resize_body)
        self.bind_all("<MouseWheel>", self._scroll_body)

    def _update_scroll_region(self, _event=None):
        self.body_canvas.configure(scrollregion=self.body_canvas.bbox("all"))

    def _resize_body(self, event):
        self.body_canvas.itemconfigure(self.body_window, width=event.width)

    def _scroll_body(self, event):
        widget = event.widget
        while widget is not None:
            if widget in (self.body, self.body_canvas):
                self.body_canvas.yview_scroll(-int(event.delta / 120), "units")
                break
            widget = getattr(widget, "master", None)

    def scroll_top(self):
        self.body_canvas.yview_moveto(0)

    def destroy(self):
        self.unbind_all("<MouseWheel>")
        super().destroy()

    def add_button(self, text, command, disabled=False, primary=False):
        b = ttk.Button(self.footer, text=text, command=command,
                       style="Accent.TButton" if primary else "TButton")
        b.pack(side="right", padx=(8, 0))
        if disabled:
            b.state(["disabled"])
        return b

    def label(self, parent, text, **kw):
        """A left-aligned, auto-wrapping label. Pack it with fill="x"."""
        kw.setdefault("wraplength", WRAP)
        kw.setdefault("justify", "left")
        kw.setdefault("anchor", "w")
        return autowrap(ttk.Label(parent, text=text, **kw))

class QuizFrame(ttk.Frame):
    """One multiple-choice question at a time with immediate feedback.
    questions: list of dict(q, options, answer, explanation, tag=None)
    on_done(results): results is a list of (tag, was_correct).
    on_show(): optional, called each time a new question is shown."""

    def __init__(self, parent, questions, on_done, on_show=None):
        super().__init__(parent)
        self.questions, self.on_done, self.on_show = questions, on_done, on_show
        self.i, self.results = 0, []
        self.var = tk.IntVar(value=-1)
        self.counter = ttk.Label(self, style="Sub.TLabel")
        self.counter.pack(anchor="w")
        self.qlabel = autowrap(ttk.Label(self, wraplength=WRAP, justify="left", anchor="w", style="Q.TLabel"))
        self.qlabel.pack(fill="x", pady=(4, 10))
        self.opts = ttk.Frame(self)
        self.opts.pack(fill="x")
        self.feedback = autowrap(ttk.Label(self, wraplength=WRAP, justify="left", anchor="w"))
        self.feedback.pack(fill="x", pady=10)
        self.btn = ttk.Button(self, style="Accent.TButton")
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
        bg = ttk.Style(self).lookup("TFrame", "background")
        for idx, text in enumerate(q["options"]):
            r = tk.Radiobutton(self.opts, text=f"{chr(65 + idx)}. {text}", variable=self.var, value=idx,
                               anchor="w", justify="left", wraplength=WRAP - 30, padx=6, pady=4,
                               background=bg, activebackground=bg, highlightthickness=0)
            autowrap(r, margin=40)
            r.pack(fill="x")
            self.radios.append(r)
        self.feedback.config(text="")
        self.btn.config(text="Submit", command=self.submit)
        if self.on_show:
            self.on_show()

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
                r.config(text="✓ " + base, disabledforeground=GREEN)
            elif idx == choice:
                r.config(text="✗ " + base, disabledforeground=RED)
        head = "Correct! " if ok else f"Not quite. The correct answer is {chr(65 + q['answer'])}. "
        self.feedback.config(text=head + q["explanation"], foreground=GREEN if ok else RED)
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
        self.images = {}              # keep references so Tk doesn't garbage-collect them
        for slide in INTRO:
            for block in slide:
                if block[0] == "img":
                    _, name, factor = block
                    img = tk.PhotoImage(file=ASSETS / name)
                    self.images[name] = img.subsample(factor, factor) if factor > 1 else img
        self.page_lbl = ttk.Label(self.body, style="Sub.TLabel")
        self.page_lbl.pack(anchor="w")
        self.slide = ttk.Frame(self.body)
        self.slide.pack(fill="both", expand=True)
        self.next_btn = self.add_button("Next", self.next, primary=True)
        self.back_btn = self.add_button("Back", self.back)
        self.refresh()

    def refresh(self):
        for w in self.slide.winfo_children():
            w.destroy()
        self.page_lbl.config(text=f"Page {self.i + 1} of {len(INTRO)}")
        first = True
        for block in INTRO[self.i]:
            kind = block[0]
            if kind == "h":
                ttk.Label(self.slide, text=block[1], style="Q.TLabel").pack(anchor="w", pady=(4 if first else 16, 6))
            elif kind == "p":
                self.label(self.slide, block[1], style="Body.TLabel").pack(fill="x", pady=(0, 10))
            elif kind == "ul":
                lst = ttk.Frame(self.slide)
                lst.pack(fill="x", pady=(0, 10))
                for item in block[1]:
                    self.label(lst, "•  " + item, style="Body.TLabel").pack(fill="x", padx=(24, 0), pady=1)
            elif kind == "img":
                ttk.Label(self.slide, image=self.images[block[1]]).pack(pady=(4, 14))
            first = False
        self.back_btn.state(["!disabled"] if self.i else ["disabled"])
        self.next_btn.config(text="Start designing" if self.i == len(INTRO) - 1 else "Next")
        self.scroll_top()

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
        self.status.pack(side="bottom", fill="x", pady=(10, 0), before=self.body_area)
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
        self.label(self.body, info["prompt"], style="Body.TLabel").pack(fill="x", pady=(4, 10))
        for value in (True, False):
            name, desc = info[value]
            box = ttk.LabelFrame(self.body, text=name, padding=12)
            box.pack(fill="x", pady=6)
            ttk.Button(box, text="Choose", command=lambda v=value, dd=d: self.choose(dd, v)).pack(side="right", padx=(16, 0))
            self.label(box, desc).pack(side="left", fill="x", expand=True)
        picked = [DECISION_INFO[k][v][0] for k, v in ch.items()]
        skipped = [DECISION_INFO[k]["name"] for k in skipped_decisions(ch)]
        text = "Your choices so far: " + (", ".join(picked) if picked else "none")
        if skipped:
            text += f"\nSkipped (not compatible with earlier choices): {', '.join(skipped)}"
        self.status.config(text=text)
        self.scroll_top()

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
        QuizFrame(self.body, qs, self.done, on_show=self.scroll_top).pack(fill="both", expand=True)

    def done(self, results):
        self.game.predictions = results
        self.app.next_screen()

class PerformanceScreen(Screen):
    TICK_MS = 100

    def __init__(self, app):
        super().__init__(app, "Performance test")
        self.label(self.body, "Enter a secret key, then watch your AES system encrypt each message "
                              "(AES-ECB). Encryption time depends on your design choices.",
                   style="Body.TLabel").pack(fill="x")
        row = ttk.Frame(self.body)
        row.pack(anchor="w", pady=12)
        ttk.Label(row, text="Secret key:").pack(side="left")
        self.entry = ttk.Entry(row, width=24)
        self.entry.pack(side="left", padx=8)
        self.entry.bind("<Return>", lambda _e: self.start())
        self.entry.focus_set()
        self.start_btn = ttk.Button(row, text="Start test", command=self.start, style="Accent.TButton")
        self.start_btn.pack(side="left")
        self.note = ttk.Label(row, text="", foreground=RED)
        self.note.pack(side="left", padx=8)

        cols = ttk.Frame(self.body)
        cols.pack(fill="both", expand=True, pady=10)
        self.left = ttk.LabelFrame(cols, text="Plaintext messages", padding=10)
        self.left.pack(side="left", fill="both", expand=True)
        mid = ttk.Frame(cols)
        mid.pack(side="left", padx=16)
        self.canvas = tk.Canvas(mid, width=190, height=150, bg="black", highlightthickness=0)
        self.canvas.pack()
        self.box_text = self.canvas.create_text(95, 75, text="Your AES system", fill="white",
                                                font=(tkfont.nametofont("TkDefaultFont").actual("family"), 12, "bold"), width=170, justify="center")
        self.bar = ttk.Progressbar(mid, length=190, maximum=100)
        self.bar.pack(pady=8)
        self.right = ttk.LabelFrame(cols, text="Ciphertext (hex)", padding=10)
        self.right.pack(side="left", fill="both", expand=True)
        self.result = ttk.Label(self.body, text="", style="Q.TLabel")
        self.result.pack(pady=(8, 0))
        self.next_btn = self.add_button("Run cache attack", self.app.next_screen, disabled=True, primary=True)

    def start(self):
        if self.start_btn.instate(["disabled"]):
            return
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
        ttk.Label(self.left, text=MESSAGES[self.idx], style="Mono.TLabel").pack(anchor="w", pady=2)
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
        ttk.Label(self.right, text=f"{ct[:16]}…{ct[-8:]}", style="Mono.TLabel").pack(anchor="w", pady=2)
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
        self.label(self.body, "The attacker will attempt to collect enough traces to recover your secret key.",
                   style="Body.TLabel").pack(fill="x")
        self.counter = ttk.Label(self.body, text="Traces collected: 0", style="Q.TLabel")
        self.counter.pack(anchor="w", pady=(14, 6))
        self.bar = ttk.Progressbar(self.body, maximum=self.STEPS)
        self.bar.pack(fill="x")
        self.outcome = self.label(self.body, "", style="Outcome.TLabel")
        self.outcome.pack(fill="x", pady=14)
        self.why = self.label(self.body, "", style="Body.TLabel")
        self.why.pack(fill="x")
        self.next_btn = self.add_button("See results", self.app.next_screen, disabled=True, primary=True)
        self.step = 0
        self.after(500, self.run)

    def run(self):
        self.step += 1
        target = NO_ATTACK_CAP if self.traces is None else min(self.traces, NO_ATTACK_CAP)
        self.bar["value"] = self.step
        self.counter.config(text=f"Traces collected: {int(target * self.step / self.STEPS):,}")
        if self.step < self.STEPS:
            self.after(60, self.run)
        else:
            self.conclude()

    def conclude(self):
        if self.traces is None or self.traces > NO_ATTACK_CAP:
            self.outcome.config(text=f"Attack failed: key NOT recovered after {NO_ATTACK_CAP:,} traces.",
                                foreground=GREEN)
        else:
            self.outcome.config(text=f"Key recovered after {self.traces:,} traces. Your Key as hexcode {self.game.key.hex()}",
                                foreground=RED)
        self.why.config(text=explain_attack(self.game.choices, self.traces))
        self.next_btn.state(["!disabled"])

class ResultsScreen(Screen):
    def __init__(self, app):
        super().__init__(app, "Your results")
        g = self.game
        box = ttk.LabelFrame(self.body, text="Your implementation choices", padding=12)
        box.pack(fill="x")
        for d in DECISIONS:
            if d in g.choices:
                v = g.choices[d]
                perf, sec = EFFECTS[(d, v)]
                ttk.Label(box, text=DECISION_INFO[d][v][0], style="Bold.TLabel").pack(anchor="w", pady=(8, 2))
                self.label(box, f"Performance: {perf}\nCache security: {sec}").pack(fill="x", padx=(16, 0))
            else:
                self.label(box, f"{DECISION_INFO[d]['name']}: skipped (not applicable to your design)",
                           style="Sub.TLabel").pack(fill="x", pady=(8, 0))
        correct = sum(ok for _, ok in g.predictions)
        total = ttk.LabelFrame(self.body, text="Overall", padding=12)
        total.pack(fill="x", pady=12)
        if g.traces is None:
            t = "no practical attack found"
        elif g.traces > NO_ATTACK_CAP:
            t = f"key not recovered in {NO_ATTACK_CAP:,} traces"
        else:
            t = f"{g.traces:,} traces to recover the key"
        self.label(total, f"Total encryption time: {g.total_time:.1f} s\n"
                          f"Cache timing attack: {t}\n"
                          f"Prediction questions correct: {correct} of {len(g.predictions)}",
                   style="Body.TLabel").pack(fill="x")
        self.label(self.body, "Want to see how a different design performs? Try a new design, "
                              "or continue to the final assessment when you're ready.",
                   style="Sub.TLabel").pack(fill="x")
        self.add_button("Final assessment", self.app.next_screen, primary=True)
        self.add_button("Try a new design", self.app.redesign)

class AssessmentScreen(Screen):
    def __init__(self, app):
        super().__init__(app, "Final assessment")
        self.quiz = QuizFrame(self.body, ASSESSMENT, self.done, on_show=self.scroll_top)
        self.quiz.pack(fill="both", expand=True)

    def done(self, results):
        score, total = sum(ok for _, ok in results), len(results)
        self.game.assessment_score, self.game.assessment_total = score, total
        self.quiz.destroy()
        ttk.Label(self.body, text=f"You scored {score} / {total}", style="Title.TLabel").pack(pady=(40, 12))
        ttk.Label(self.body, text="Thank you for playing our game! You can play again if you would like.",
                  style="Body.TLabel").pack()
        self.scroll_top()
        self.add_button("Quit", self.app.destroy)
        self.add_button("Play again", self.app.restart, primary=True)

#  -------------------- app --------------------
class App(tk.Tk):
    FLOW = [IntroScreen, DesignScreen, PredictScreen, PerformanceScreen, AttackScreen,
            ResultsScreen, AssessmentScreen]

    def __init__(self):
        super().__init__()
        self.title("AES Implementation Lab")
        self.geometry("960x760")
        self.minsize(820, 620)
        self._setup_style()
        self.game = GameState()
        self.index, self.current = -1, None
        self.next_screen()

    def _setup_style(self):
        # Use the platform's default font everywhere (Segoe UI on Windows, SF on macOS, etc.).
        for name in ("TkDefaultFont", "TkTextFont"):
            tkfont.nametofont(name).configure(size=11)
        tkfont.nametofont("TkFixedFont").configure(size=11)
        family = tkfont.nametofont("TkDefaultFont").actual("family")
        style = ttk.Style(self)
        style.configure("Title.TLabel", font=(family, 20, "bold"))
        style.configure("Q.TLabel", font=(family, 14, "bold"))
        style.configure("Bold.TLabel", font=(family, 11, "bold"))
        style.configure("Body.TLabel", font=(family, 12))
        style.configure("Outcome.TLabel", font=(family, 13, "bold"))
        style.configure("Sub.TLabel", foreground="gray40")
        style.configure("Mono.TLabel", font="TkFixedFont")
        style.configure("TLabelframe.Label", font=(family, 11, "bold"))
        style.configure("TButton", padding=(10, 4))
        style.configure("Accent.TButton", padding=(10, 4), font=(family, 11, "bold"))

    def next_screen(self):
        if self.current is not None:
            self.current.destroy()
        self.index += 1
        self.current = self.FLOW[self.index](self)
        self.current.pack(fill="both", expand=True)

    def redesign(self):
        """Clear the current design and go back to the first design decision."""
        self.game = GameState()
        self.index = self.FLOW.index(DesignScreen) - 1
        self.next_screen()

    def restart(self):
        self.game = GameState()
        self.index = -1
        self.next_screen()

if __name__ == "__main__":
    App().mainloop()
