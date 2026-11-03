"""

Fighting the Cacherssssssssssssssss woooooo
Run with:  python main.py

1) content  2) game rules  3) aes engine  4) ui helpers  5) screens  6) app

"""
import tkinter as tk
from dataclasses import dataclass, field
from tkinter import ttk
from typing import Optional
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# ------------------- content -------------------
INTRO = [
    ("intro question 1",
     "something "
     "something"),
    ("intro question 2",
     "something "
     "something"),
    ("intro question 3",
     "something "
     "something "
     "something"),
    ("intro question 4",
     "something "
     "something"),
]

DECISION_INFO = {
    "sbox": {
        "title": "Decision 1: placeholder_decision_title_1",
        "prompt": "placeholder_decision_prompt_1",
        True: ("placeholder_option_name_1", "placeholder_option_description_1"),
        False: ("placeholder_option_name_2", "placeholder_option_description_2"),
    },
    "ttable": {
        "title": "Decision 2: placeholder_decision_title_2",
        "prompt": "placeholder_decision_prompt_2",
        True: ("placeholder_option_name_3", "placeholder_option_description_3"),
        False: ("placeholder_option_name_4", "placeholder_option_description_4"),
    },
    "masking": {
        "title": "Decision 3: placeholder_decision_title_3",
        "prompt": "placeholder_decision_prompt_3",
        True: ("placeholder_option_name_5", "placeholder_option_description_5"),
        False: ("placeholder_option_name_6", "placeholder_option_description_6"),
    },
    "hw": {
        "title": "Decision 4: placeholder_decision_title_4",
        "prompt": "placeholder_decision_prompt_4",
        True: ("placeholder_option_name_7", "placeholder_option_description_7"),
        False: ("placeholder_option_name_8", "placeholder_option_description_8"),
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
    return dict(q=f"question {n} placeholder",
                options=[f"answer {k} placeholder" for k in range(1, 5)],
                answer=0, explanation="explanation placeholder")

# Prediction phase: one question per decision the student made (numbered in order shown).
# To write real ones, build them in PredictScreen from the student's choice (see that class).
NUM_ASSESSMENT_QUESTIONS = 10
ASSESSMENT = [placeholder_question(n) for n in range(1, NUM_ASSESSMENT_QUESTIONS + 1)]

# ------------------- game rules --------------------
DECISIONS = ["sbox", "ttable", "masking", "hw"]

# Performance parameters and their sources (for the simulation, not real numbers):
BASE_DELAY = 10          # seconds per message for the slowest implementation

SBOX_SPEEDUP = 10       # table lookup instead of computing SubBytes 
# (https://scispace.com/pdf/timing-attack-on-a-modified-dynamic-s-box-implementation-of-5dpgjkgbhx.pdf) Found that S-box lookup is 10 times faster than computing SubBytes
TTABLE_SPEEDUP = 0.25     # merged round tables instead of separate steps
# (https://rd.springer.com/content/pdf/10.1007/11552055_2.pdf) Found that best case T-tables decrease cycle count from 1600 to 1200, for 25% speedup
MASKING_OVERHEAD = 9.37   # boolean masking cost
# (https://link.springer.com/content/pdf/10.1007/978-3-540-72738-5_10.pdf) Assuming just masking to S-box lookups, with strong randomization for strongests masking security, best case overhead is increasing from 1637 cycles to 15,332 cycles, for 9.37 times more cycles
HW_SPEEDUP = 0.829          # dedicated AES instructions multiply remaining time
# (https://www.intel.com/content/dam/develop/external/us/en/documents/10tb24-breakthrough-aes-performance-with-intel-aes-new-instructions-final-secure-165683.pdf) showed off AES-NI, which reduced the cycle count to ~1.3 cycles/byte, compared to a baseline (https://eprint.iacr.org/2009/129.pdf) of 7.59 cycles/byte for AES-128, this is a 82.9% speedup

TRACES_SBOX = 2_000       # traces to recover key: S-box only
TRACES_TTABLE = 500       # traces to recover key: T-tables
MASKING_MULTIPLIER = 200  # masking makes the attack this many times harder
NO_ATTACK_CAP = 100_000   # traces the simulated attacker tries before giving up

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
    return n * MASKING_MULTIPLIER if choices.get("masking") else n

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
        self.body = ttk.Frame(self)
        self.body.pack(fill="both", expand=True)
        self.footer = ttk.Frame(self)
        self.footer.pack(fill="x", pady=(12, 0))

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
        self.next_btn = self.add_button("Next", self.next)
        self.back_btn = self.add_button("Back", self.back)
        self.refresh()

    def refresh(self):
        t, b = INTRO[self.i]
        self.title_lbl.config(text=f"{self.i + 1}/{len(INTRO)}  {t}")
        self.text_lbl.config(text=b)
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
        made = [d for d in DECISIONS if d in self.game.choices]   # one question per decision made
        qs = []
        for n, d in enumerate(made, start=1):
            q = placeholder_question(n)   # <- replace with a real question for decision d / choice self.game.choices[d]
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
            self.result.config(text=f"Total encryption time: {self.delay:.1f} s")
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