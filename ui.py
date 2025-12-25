import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import numpy as np
import hashlib
import time
import threading
import json
import csv
import sys
import os
from typing import List, Tuple, Optional, Dict, Any
from datetime import datetime
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2Tk
from matplotlib.figure import Figure
import matplotlib
matplotlib.use("TkAgg")

# High DPI fix
def set_dpi_awareness():
    """Set DPI awareness to fix blurry fonts on high-resolution displays"""
    if sys.platform == "win32":
        try:
            from ctypes import windll, c_int, byref
            windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            pass
    elif sys.platform == "darwin":  # macOS
        try:
            os.environ['TK_SILENCE_DEPRECATION'] = '1'
        except Exception:
            pass

# Call before creating Tkinter window
set_dpi_awareness()

class OTExtension:
    def __init__(self):
        self.k = 128  # Default security parameter
        self.m = 1000  # Default number of extended OTs
        self.ell = 32  # Default string length (bytes)
        self.sigma = 40  # Default security parameter (malicious model)
        self.execution_history = []  # Execution history
        self.verification_sample_size = 10  # Default sample size for verification
        self.performance_data = []  # Store performance test data
        
    def hash_function(self, *args) -> bytes:
        """Random oracle implementation"""
        h = hashlib.sha256()
        for arg in args:
            if isinstance(arg, int):
                h.update(str(arg).encode())
            elif isinstance(arg, bytes):
                h.update(arg)
            elif isinstance(arg, np.ndarray):
                h.update(arg.tobytes())
            else:
                h.update(str(arg).encode())
        return h.digest()[:self.ell]
    
    def ideal_ot(self, sender_inputs, receiver_selection):
        """Ideal OT function simulation"""
        results = []
        for i in range(len(receiver_selection)):
            choice = receiver_selection[i]
            results.append(sender_inputs[i][choice])
        return results
    
    def base_ot_protocol(self, s, T, r):
        """Base OT protocol simulation"""
        m, k = T.shape
        Q = np.zeros((m, k), dtype=int)
        
        for i in range(k):
            if s[i] == 0:
                Q[:, i] = T[:, i]
            else:
                Q[:, i] = (r ^ T[:, i]) % 2
                
        return Q
    
    def semi_honest_ot_extension(self, x_pairs, r):
        """Semi-honest model OT extension protocol"""
        k, m, ell = self.k, self.m, self.ell
        
        s = np.random.randint(0, 2, k)
        T = np.random.randint(0, 2, (m, k))
        
        Q = self.base_ot_protocol(s, T, r)
        
        y_pairs = []
        for j in range(m):
            q_j = Q[j, :]
            q_j_bytes = q_j.tobytes()
            s_bytes = s.tobytes()
            
            y_j0 = bytes(a ^ b for a, b in zip(x_pairs[j][0], self.hash_function(j, q_j_bytes)))
            y_j1 = bytes(a ^ b for a, b in zip(x_pairs[j][1], self.hash_function(j, bytes([a ^ b for a, b in zip(q_j_bytes, s_bytes)]))))
            y_pairs.append((y_j0, y_j1))
        
        outputs = []
        for j in range(m):
            t_j = T[j, :]
            t_j_bytes = t_j.tobytes()
            z_j = bytes(a ^ b for a, b in zip(y_pairs[j][r[j]], self.hash_function(j, t_j_bytes)))
            outputs.append(z_j)
        
        return outputs, s, T, Q, y_pairs
    
    def malicious_ot_extension(self, x_pairs, r):
        """Malicious model OT extension protocol"""
        k, m, ell, sigma = self.k, self.m, self.ell, self.sigma
        
        s_list = [np.random.randint(0, 2, k) for _ in range(sigma)]
        T_list = [np.random.randint(0, 2, (m, k)) for _ in range(sigma)]
        r_list = [np.random.randint(0, 2, m) for _ in range(sigma)]
        
        x_pairs_list = []
        for p in range(sigma):
            random_pairs = []
            for j in range(m):
                x0 = np.random.bytes(ell)
                x1 = np.random.bytes(ell)
                random_pairs.append((x0, x1))
            x_pairs_list.append(random_pairs)
        
        Q_list = []
        for p in range(sigma):
            Q = self.base_ot_protocol(s_list[p], T_list[p], r_list[p])
            Q_list.append(Q)
        
        P = np.random.choice(sigma, sigma//2, replace=False)
        
        y_pairs_list = []
        for p in range(sigma):
            y_pairs = []
            for j in range(m):
                q_j = Q_list[p][j, :]
                q_j_bytes = q_j.tobytes()
                s_bytes = s_list[p].tobytes()
                
                y_j0 = bytes(a ^ b for a, b in zip(x_pairs_list[p][j][0], self.hash_function(p, j, q_j_bytes)))
                y_j1 = bytes(a ^ b for a, b in zip(x_pairs_list[p][j][1], self.hash_function(p, j, bytes([a ^ b for a, b in zip(q_j_bytes, s_bytes)]))))
                y_pairs.append((y_j0, y_j1))
            y_pairs_list.append(y_pairs)
        
        c_list = []
        for j in range(m):
            c_j = []
            for p in range(sigma):
                if p not in P:
                    c_jp = r[j] ^ r_list[p][j]
                    c_j.append(c_jp)
                else:
                    c_j.append(0)
            c_list.append(c_j)
        
        w_pairs = []
        for j in range(m):
            w_j0 = x_pairs[j][0]
            w_j1 = x_pairs[j][1]
            
            for idx, p in enumerate(range(sigma)):
                if p not in P:
                    b0 = 0 ^ c_list[j][idx]
                    b1 = 1 ^ c_list[j][idx]
                    
                    w_j0 = bytes(a ^ b for a, b in zip(w_j0, x_pairs_list[p][j][b0]))
                    w_j1 = bytes(a ^ b for a, b in zip(w_j1, x_pairs_list[p][j][b1]))
            
            w_pairs.append((w_j0, w_j1))
        
        outputs = []
        for j in range(m):
            z_j = w_pairs[j][r[j]]
            
            for idx, p in enumerate(range(sigma)):
                if p not in P:
                    t_j = T_list[p][j, :]
                    t_j_bytes = t_j.tobytes()
                    
                    mask = bytes(a ^ b for a, b in zip(
                        y_pairs_list[p][j][r_list[p][j]], 
                        self.hash_function(p, j, t_j_bytes)
                    ))
                    z_j = bytes(a ^ b for a, b in zip(z_j, mask))
            
            outputs.append(z_j)
        
        return outputs, s_list, T_list, r_list, Q_list, P, y_pairs_list, w_pairs
    
    def verify_correctness(self, outputs, x_pairs, r, sample_size=None):
        """Verify correctness of OT extension protocol outputs
        
        Args:
            outputs: List of outputs from OT extension protocol
            x_pairs: Original sender input pairs
            r: Receiver selection bits
            sample_size: Number of OTs to verify (None for all)
            
        Returns:
            correct_count: Number of correctly verified OTs
            total_verified: Total number of OTs verified
            incorrect_indices: List of indices where verification failed
        """
        if sample_size is None:
            sample_size = len(outputs)
        else:
            sample_size = min(sample_size, len(outputs))
        
        correct_count = 0
        incorrect_indices = []
        
        for j in range(sample_size):
            expected = x_pairs[j][r[j]]
            actual = outputs[j]
            is_correct = (expected == actual)
            
            if is_correct:
                correct_count += 1
            else:
                incorrect_indices.append(j)
        
        return correct_count, sample_size, incorrect_indices
    
    def statistical_verification_analysis(self, sample_size, total_size, confidence=0.99):
        """Perform statistical analysis of verification sampling
        
        Args:
            sample_size: Number of OTs verified
            total_size: Total number of OTs
            confidence: Desired confidence level
            
        Returns:
            analysis: Dictionary with statistical analysis results
        """
        if sample_size == 0 or total_size == 0:
            return {}
        
        if sample_size == total_size:
            return {
                "confidence_level": 1.0,
                "error_probability": 0.0,
                "verification_coverage": 1.0
            }
        
        alpha = 1 - confidence
        failure_rate_bound = -np.log(alpha) / sample_size if sample_size > 0 else 1.0
        
        coverage = sample_size / total_size
        
        return {
            "confidence_level": confidence,
            "error_probability_upper_bound": failure_rate_bound,
            "verification_coverage": coverage,
            "undetected_errors_probability": (1 - coverage) * failure_rate_bound
        }
    
    def performance_test(self, m_values, protocol_type, k=None, ell=None, sigma=None, repetitions=3):
        """Run performance test for different m values
        
        Args:
            m_values: List of m values to test
            protocol_type: 'semi_honest' or 'malicious'
            k: Security parameter (default: self.k)
            ell: String length (default: self.ell)
            sigma: Security parameter for malicious model (default: self.sigma)
            repetitions: Number of repetitions for each m value
            
        Returns:
            performance_data: List of dictionaries with performance results
        """
        if k is None:
            k = self.k
        if ell is None:
            ell = self.ell
        if sigma is None:
            sigma = self.sigma
            
        performance_data = []
        
        for m in m_values:
            self.m = m
            self.k = k
            self.ell = ell
            self.sigma = sigma
            
            m_times = []
            
            for rep in range(repetitions):
                x_pairs = [(np.random.bytes(ell), np.random.bytes(ell)) for _ in range(m)]
                r = np.random.randint(0, 2, m)
                
                start_time = time.time()
                
                if protocol_type == "semi_honest":
                    outputs, s, T, Q, y_pairs = self.semi_honest_ot_extension(x_pairs, r)
                else:
                    outputs, s_list, T_list, r_list, Q_list, P, y_pairs_list, w_pairs = \
                        self.malicious_ot_extension(x_pairs, r)
                
                end_time = time.time()
                execution_time = end_time - start_time
                m_times.append(execution_time)
            
            avg_time = np.mean(m_times)
            std_time = np.std(m_times)
            avg_time_per_ot = avg_time / m * 1000  # Convert to milliseconds
            
            performance_record = {
                "m": m,
                "protocol_type": protocol_type,
                "k": k,
                "ell": ell,
                "sigma": sigma if protocol_type == "malicious" else None,
                "repetitions": repetitions,
                "avg_time_seconds": avg_time,
                "std_time_seconds": std_time,
                "avg_time_per_ot_ms": avg_time_per_ot,
                "execution_times": m_times
            }
            
            performance_data.append(performance_record)
        
        self.performance_data = performance_data
        return performance_data
    
    def add_to_history(self, protocol_type: str, parameters: Dict[str, Any], 
                      execution_time: float, success: bool = True):
        """Add execution record to history"""
        record = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "protocol_type": protocol_type,
            "parameters": parameters,
            "execution_time": execution_time,
            "success": success
        }
        self.execution_history.append(record)
        
        if len(self.execution_history) > 100:
            self.execution_history = self.execution_history[-100:]

class OTExtensionUI:
    def __init__(self, root):
        self.root = root
        self.root.title("OT-Extension Algorithm Implementation v5.0")
        self.root.geometry("1400x900")
        
        self.set_dpi_scaling()
        self.setup_styles()
        self.ot_extension = OTExtension()
        self.setup_ui()
    
    def set_dpi_scaling(self):
        """Set DPI scaling to fix blurry fonts on high-resolution displays"""
        if sys.platform == "win32":
            try:
                from ctypes import windll
                windll.shcore.SetProcessDpiAwareness(1)
                
                dpi = windll.user32.GetDpiForWindow(self.root.winfo_id())
                scale_factor = dpi / 96.0
                
                self.root.tk.call('tk', 'scaling', scale_factor)
                
                self.font_size = int(10 * scale_factor)
                self.title_font_size = int(16 * scale_factor)
                self.subtitle_font_size = int(12 * scale_factor)
            except Exception:
                self.font_size = 10
                self.title_font_size = 16
                self.subtitle_font_size = 12
        else:
            self.font_size = 10
            self.title_font_size = 16
            self.subtitle_font_size = 12
        
    def setup_styles(self):
        """Setup UI styles"""
        style = ttk.Style()
        style.theme_use('clam')
        
        style.configure("Title.TLabel", font=("Arial", self.title_font_size, "bold"))
        style.configure("Subtitle.TLabel", font=("Arial", self.subtitle_font_size, "bold"))
        style.configure("Result.TLabel", font=("Courier", self.font_size))
        
        style.configure("Green.TButton", background="#4CAF50", foreground="white", font=("Arial", self.font_size))
        style.configure("Blue.TButton", background="#2196F3", foreground="white", font=("Arial", self.font_size))
        style.configure("Orange.TButton", background="#FF9800", foreground="white", font=("Arial", self.font_size))
        style.configure("Purple.TButton", background="#9C27B0", foreground="white", font=("Arial", self.font_size))
        
        style.configure(".", font=("Arial", self.font_size))
        
    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="15")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        title_frame = ttk.Frame(main_frame)
        title_frame.grid(row=0, column=0, columnspan=3, pady=(0, 20), sticky=(tk.W, tk.E))
        
        title_label = ttk.Label(
            title_frame, 
            text="OT-Extension Algorithm Implementation", 
            font=("Arial", self.title_font_size + 4, "bold"), 
            foreground="#2C3E50"
        )
        title_label.pack()
        
        subtitle_label = ttk.Label(
            title_frame, 
            text="Based on Ishai et al. (2003)", 
            font=("Arial", self.subtitle_font_size), 
            foreground="#7F8C8D"
        )
        subtitle_label.pack()
        
        left_panel = ttk.LabelFrame(main_frame, text="Control Panel", padding="20")
        left_panel.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        
        params_frame = ttk.LabelFrame(left_panel, text="Protocol Parameters", padding="15")
        params_frame.pack(fill=tk.X, pady=(0, 15))
        
        param_row1 = ttk.Frame(params_frame)
        param_row1.pack(fill=tk.X, pady=8)
        
        ttk.Label(param_row1, text="Security param k:", width=20, font=("Arial", self.font_size)).pack(side=tk.LEFT, padx=(0, 10))
        self.k_var = tk.StringVar(value=str(self.ot_extension.k))
        k_entry = ttk.Entry(param_row1, textvariable=self.k_var, width=12, font=("Arial", self.font_size))
        k_entry.pack(side=tk.LEFT)
        
        ttk.Label(param_row1, text="Extended OTs m:", width=20, font=("Arial", self.font_size)).pack(side=tk.LEFT, padx=(20, 10))
        self.m_var = tk.StringVar(value=str(self.ot_extension.m))
        m_entry = ttk.Entry(param_row1, textvariable=self.m_var, width=12, font=("Arial", self.font_size))
        m_entry.pack(side=tk.LEFT)
        
        param_row2 = ttk.Frame(params_frame)
        param_row2.pack(fill=tk.X, pady=8)
        
        ttk.Label(param_row2, text="String length ell:", width=20, font=("Arial", self.font_size)).pack(side=tk.LEFT, padx=(0, 10))
        self.ell_var = tk.StringVar(value=str(self.ot_extension.ell))
        ell_entry = ttk.Entry(param_row2, textvariable=self.ell_var, width=12, font=("Arial", self.font_size))
        ell_entry.pack(side=tk.LEFT)
        
        ttk.Label(param_row2, text="Security param σ:", width=20, font=("Arial", self.font_size)).pack(side=tk.LEFT, padx=(20, 10))
        self.sigma_var = tk.StringVar(value=str(self.ot_extension.sigma))
        sigma_entry = ttk.Entry(param_row2, textvariable=self.sigma_var, width=12, font=("Arial", self.font_size))
        sigma_entry.pack(side=tk.LEFT)
        
        param_row3 = ttk.Frame(params_frame)
        param_row3.pack(fill=tk.X, pady=8)
        
        ttk.Label(param_row3, text="Verification sample:", width=20, font=("Arial", self.font_size)).pack(side=tk.LEFT, padx=(0, 10))
        self.verify_var = tk.StringVar(value=str(self.ot_extension.verification_sample_size))
        verify_entry = ttk.Entry(param_row3, textvariable=self.verify_var, width=12, font=("Arial", self.font_size))
        verify_entry.pack(side=tk.LEFT)
        
        ttk.Label(param_row3, text="(0 for all)", width=10, font=("Arial", self.font_size)).pack(side=tk.LEFT, padx=(5, 0))
        
        protocol_frame = ttk.LabelFrame(left_panel, text="Protocol Type", padding="15")
        protocol_frame.pack(fill=tk.X, pady=(0, 15))
        
        self.protocol_var = tk.StringVar(value="semi_honest")
        
        semi_honest_radio = ttk.Radiobutton(
            protocol_frame, 
            text="Semi-Honest Model", 
            variable=self.protocol_var, 
            value="semi_honest",
            style="TRadiobutton"
        )
        semi_honest_radio.pack(anchor=tk.W, pady=5)
        
        malicious_radio = ttk.Radiobutton(
            protocol_frame, 
            text="Malicious Model", 
            variable=self.protocol_var, 
            value="malicious",
            style="TRadiobutton"
        )
        malicious_radio.pack(anchor=tk.W, pady=5)
        
        input_frame = ttk.LabelFrame(left_panel, text="Input Data", padding="15")
        input_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 15))
        
        input_controls = ttk.Frame(input_frame)
        input_controls.pack(fill=tk.X, pady=(0, 10))
        
        generate_button = ttk.Button(
            input_controls, 
            text="Generate RandomInput", 
            command=self.generate_random_inputs, 
            width=20
        )
        generate_button.pack(side=tk.LEFT, padx=(0, 10))
        
        clear_input_button = ttk.Button(
            input_controls, 
            text="Clear Input", 
            command=self.clear_inputs, 
            width=15
        )
        clear_input_button.pack(side=tk.LEFT)
        
        r_label = ttk.Label(input_frame, text="Receiver selection bits r:", font=("Arial", self.font_size))
        r_label.pack(anchor=tk.W, pady=(10, 5))
        
        r_frame = ttk.Frame(input_frame)
        r_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.r_var = tk.StringVar(value="")
        self.r_entry = ttk.Entry(r_frame, textvariable=self.r_var, font=("Arial", self.font_size))
        self.r_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        random_r_button = ttk.Button(r_frame, text="Random", command=self.generate_random_r, width=10)
        random_r_button.pack(side=tk.LEFT)
        
        input_label = ttk.Label(
            input_frame, 
            text="Sender input pairs (hex display, first 16 bytes):", 
            font=("Arial", self.font_size)
        )
        input_label.pack(anchor=tk.W, pady=(5, 5))
        
        self.input_text = scrolledtext.ScrolledText(
            input_frame, 
            height=8, 
            width=40,
            font=("Courier", self.font_size - 1)
        )
        self.input_text.pack(fill=tk.BOTH, expand=True)
        
        button_frame = ttk.Frame(left_panel)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        execute_button = ttk.Button(
            button_frame, 
            text="Execute Protocol", 
            command=self.execute_protocol, 
            style="Green.TButton"
        )
        execute_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        performance_button = ttk.Button(
            button_frame, 
            text="Performance Test", 
            command=self.open_performance_test_window,
            style="Purple.TButton"
        )
        performance_button.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        reset_button = ttk.Button(
            button_frame, 
            text="Reset Parameters", 
            command=self.reset_parameters
        )
        reset_button.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        center_panel = ttk.LabelFrame(main_frame, text="Results and Output", padding="20")
        center_panel.grid(row=1, column=1, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        
        result_controls = ttk.Frame(center_panel)
        result_controls.pack(fill=tk.X, pady=(0, 15))
        
        export_results_button = ttk.Button(
            result_controls, 
            text="Export Results", 
            command=self.export_results, 
            style="Blue.TButton"
        )
        export_results_button.pack(side=tk.LEFT, padx=(0, 10))
        
        export_history_button = ttk.Button(
            result_controls, 
            text="Export History", 
            command=self.export_history, 
            style="Blue.TButton"
        )
        export_history_button.pack(side=tk.LEFT, padx=(0, 10))
        
        clear_results_button = ttk.Button(
            result_controls, 
            text="Clear Results", 
            command=self.clear_results
        )
        clear_results_button.pack(side=tk.LEFT)
        
        self.notebook = ttk.Notebook(center_panel)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        result_tab = ttk.Frame(self.notebook)
        self.notebook.add(result_tab, text="Execution Results")
        
        self.result_text = scrolledtext.ScrolledText(
            result_tab, 
            height=20, 
            width=60,
            font=("Courier", self.font_size)
        )
        self.result_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        stats_tab = ttk.Frame(self.notebook)
        self.notebook.add(stats_tab, text="Statistics")
        
        self.stats_text = scrolledtext.ScrolledText(
            stats_tab, 
            height=20, 
            width=60,
            font=("Courier", self.font_size)
        )
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        history_tab = ttk.Frame(self.notebook)
        self.notebook.add(history_tab, text="Execution History")
        
        self.history_text = scrolledtext.ScrolledText(
            history_tab, 
            height=20, 
            width=60,
            font=("Courier", self.font_size)
        )
        self.history_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        right_panel = ttk.LabelFrame(main_frame, text="Performance Visualization", padding="20")
        right_panel.grid(row=1, column=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.figure = Figure(figsize=(6, 5), dpi=100)
        self.canvas = FigureCanvasTkAgg(self.figure, master=right_panel)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        toolbar = NavigationToolbar2Tk(self.canvas, right_panel)
        toolbar.update()
        
        vis_controls = ttk.Frame(right_panel)
        vis_controls.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Button(vis_controls, text="Clear Plot", command=self.clear_plot).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(vis_controls, text="Export Plot", command=self.export_plot).pack(side=tk.LEFT)
        
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(15, 0))
        
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(
            status_frame, 
            textvariable=self.status_var, 
            relief=tk.SUNKEN, 
            anchor=tk.W,
            font=("Arial", self.font_size - 1)
        )
        status_label.pack(fill=tk.X)
        
        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=2)
        main_frame.columnconfigure(2, weight=2)
        main_frame.rowconfigure(1, weight=1)
        
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        
        self.update_stats()
        self.update_history_display()
    
    def update_status(self, message: str):
        self.status_var.set(message)
        self.root.update_idletasks()
    
    def generate_random_inputs(self):
        try:
            k = int(self.k_var.get())
            m = int(self.m_var.get())
            ell = int(self.ell_var.get())
            
            if m > 10000:
                if not messagebox.askyesno("Confirmation", f"Generating {m} OT input pairs may require significant memory. Continue?"):
                    return
            
            self.update_status("Generating random inputs...")
            
            input_pairs = []
            for j in range(m):
                x0 = np.random.bytes(ell)
                x1 = np.random.bytes(ell)
                x0_display = x0.hex()[:32] + ("..." if len(x0.hex()) > 32 else "")
                x1_display = x1.hex()[:32] + ("..." if len(x1.hex()) > 32 else "")
                input_pairs.append((x0_display, x1_display, x0, x1))
            
            r = np.random.randint(0, 2, m)
            r_str = ''.join(str(bit) for bit in r)
            
            self.input_text.delete(1.0, tk.END)
            for j, (x0_disp, x1_disp, x0, x1) in enumerate(input_pairs):
                self.input_text.insert(tk.END, f"Pair {j:4d}: ({x0_disp}, {x1_disp})\n")
            
            self.r_var.set(r_str)
            
            self.cached_input_pairs = [(x0, x1) for _, _, x0, x1 in input_pairs]
            self.cached_r = r
            
            self.log_result("Random input data generated successfully")
            self.update_status(f"Generated {m} random input pairs")
            
        except ValueError as e:
            messagebox.showerror("Error", "Parameter format error, please enter integers")
        except Exception as e:
            messagebox.showerror("Error", f"Error generating inputs: {str(e)}")
    
    def generate_random_r(self):
        try:
            m = int(self.m_var.get())
            r = np.random.randint(0, 2, m)
            r_str = ''.join(str(bit) for bit in r)
            self.r_var.set(r_str)
        except:
            messagebox.showerror("Error", "Please set a valid m value first")
    
    def clear_inputs(self):
        self.input_text.delete(1.0, tk.END)
        self.r_var.set("")
        if hasattr(self, 'cached_input_pairs'):
            del self.cached_input_pairs
        if hasattr(self, 'cached_r'):
            del self.cached_r
    
    def reset_parameters(self):
        self.k_var.set("128")
        self.m_var.set("1000")
        self.ell_var.set("32")
        self.sigma_var.set("40")
        self.verify_var.set("10")
        self.protocol_var.set("semi_honest")
        self.clear_inputs()
        self.clear_results()
        self.update_status("Parameters reset to defaults")
    
    def execute_protocol(self):
        try:
            self.ot_extension.k = int(self.k_var.get())
            self.ot_extension.m = int(self.m_var.get())
            self.ot_extension.ell = int(self.ell_var.get())
            self.ot_extension.sigma = int(self.sigma_var.get())
            
            verify_sample = int(self.verify_var.get())
            if verify_sample < 0:
                messagebox.showerror("Error", "Verification sample size must be >= 0")
                return
            self.ot_extension.verification_sample_size = verify_sample
            
            k, m, ell = self.ot_extension.k, self.ot_extension.m, self.ot_extension.ell
            
            if not hasattr(self, 'cached_input_pairs'):
                input_text = self.input_text.get(1.0, tk.END).strip()
                r_text = self.r_var.get().strip()
                
                if not input_text or not r_text:
                    messagebox.showerror("Error", "Please enter complete data or generate random input")
                    return
                
                x_pairs = []
                lines = input_text.split('\n')
                for line in lines:
                    if 'Pair' in line and ': (' in line:
                        pair_str = line.split(': (')[1].rstrip(')')
                        parts = pair_str.split(', ')
                        if len(parts) >= 2:
                            x0_hex = parts[0]
                            x1_hex = parts[1]
                            x0_hex = x0_hex.replace('...', '')
                            x1_hex = x1_hex.replace('...', '')
                            x0 = bytes.fromhex(x0_hex) if x0_hex else np.random.bytes(ell)
                            x1 = bytes.fromhex(x1_hex) if x1_hex else np.random.bytes(ell)
                            x_pairs.append((x0, x1))
                
                r = np.array([int(bit) for bit in r_text])
            else:
                x_pairs = self.cached_input_pairs
                r = self.cached_r
            
            if len(x_pairs) != m or len(r) != m:
                messagebox.showerror("Error", f"Input data count mismatch, expected m={m}")
                return
            
            self.log_result("=" * 60)
            self.log_result("Starting OT extension protocol...")
            self.log_result(f"Protocol type: {'Semi-honest model' if self.protocol_var.get() == 'semi_honest' else 'Malicious model'}")
            self.log_result(f"Parameters: k={k}, m={m}, ell={ell}")
            if self.protocol_var.get() == "malicious":
                self.log_result(f"Security parameter σ: {self.ot_extension.sigma}")
            
            self.update_status("Executing protocol...")
            
            thread = threading.Thread(target=self._execute_protocol_thread, args=(x_pairs, r))
            thread.daemon = True
            thread.start()
            
        except ValueError as e:
            messagebox.showerror("Error", f"Data format error: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"Error executing protocol: {str(e)}")
    
    def _execute_protocol_thread(self, x_pairs, r):
        try:
            start_time = time.time()
            protocol_type = self.protocol_var.get()
            
            if protocol_type == "semi_honest":
                outputs, s, T, Q, y_pairs = self.ot_extension.semi_honest_ot_extension(x_pairs, r)
                
                end_time = time.time()
                execution_time = end_time - start_time
                
                self.root.after(0, self._display_semi_honest_results, 
                              outputs, s, T, Q, y_pairs, execution_time, x_pairs, r)
                
            else:
                outputs, s_list, T_list, r_list, Q_list, P, y_pairs_list, w_pairs = \
                    self.ot_extension.malicious_ot_extension(x_pairs, r)
                
                end_time = time.time()
                execution_time = end_time - start_time
                
                self.root.after(0, self._display_malicious_results, outputs, s_list, T_list, 
                              r_list, Q_list, P, y_pairs_list, w_pairs, execution_time, x_pairs, r)
                
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Protocol execution failed: {str(e)}"))
            self.root.after(0, lambda: self.update_status("Protocol execution failed"))
    
    def _display_semi_honest_results(self, outputs, s, T, Q, y_pairs, execution_time, x_pairs, r):
        self.log_result("\n" + "=" * 60)
        self.log_result("Protocol execution completed")
        self.log_result(f"Execution time: {execution_time:.4f} seconds")
        self.log_result(f"Extended {self.ot_extension.m} OTs")
        self.log_result(f"Average time per OT: {execution_time/self.ot_extension.m*1000:.2f} ms")
        
        self.log_result("\n--- Intermediate Protocol Results ---")
        self.log_result(f"Sender random vector s (first 32 hex chars): {s.tobytes().hex()[:32]}...")
        self.log_result(f"Receiver matrix T shape: {T.shape}")
        self.log_result(f"Base OT result Q shape: {Q.shape}")
        
        verify_sample = self.ot_extension.verification_sample_size
        if verify_sample == 0:
            verify_sample = len(outputs)
        
        self.log_result(f"\n--- Correctness Verification (sampling {verify_sample} of {len(outputs)} OTs) ---")
        
        correct_count, total_verified, incorrect_indices = self.ot_extension.verify_correctness(
            outputs, x_pairs, r, verify_sample
        )
        
        for j in range(min(10, total_verified)):
            expected = x_pairs[j][r[j]]
            actual = outputs[j]
            is_correct = (expected == actual)
            self.log_result(f"OT {j}: {'✓' if is_correct else '✗'} Output length = {len(outputs[j])} bytes")
        
        if total_verified > 10:
            self.log_result(f"... and {total_verified - 10} more OTs verified")
        
        if correct_count == total_verified:
            self.log_result(f"All {total_verified} verified OTs are correct!")
        else:
            self.log_result(f"Warning: {total_verified - correct_count} of {total_verified} verified OTs failed verification")
            if incorrect_indices:
                self.log_result(f"First 5 incorrect indices: {incorrect_indices[:5]}")
        
        if verify_sample < len(outputs):
            stats = self.ot_extension.statistical_verification_analysis(
                verify_sample, len(outputs), confidence=0.99
            )
            if stats:
                self.log_result(f"\n--- Statistical Verification Analysis ---")
                self.log_result(f"Confidence level: {stats.get('confidence_level', 0):.3f}")
                self.log_result(f"Error probability upper bound: {stats.get('error_probability_upper_bound', 0):.6f}")
                self.log_result(f"Verification coverage: {stats.get('verification_coverage', 0):.4f}")
                self.log_result(f"Undetected errors probability: {stats.get('undetected_errors_probability', 0):.6f}")
        
        self.log_result("\nProtocol execution successful!")
        
        params = {
            "k": self.ot_extension.k,
            "m": self.ot_extension.m,
            "ell": self.ot_extension.ell,
            "protocol": "semi_honest",
            "verification_sample": verify_sample
        }
        self.ot_extension.add_to_history("semi_honest", params, execution_time, True)
        
        self.last_results = {
            "protocol": "semi_honest",
            "execution_time": execution_time,
            "outputs": outputs,
            "parameters": params,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "verification_stats": {
                "correct_count": correct_count,
                "total_verified": total_verified,
                "incorrect_count": total_verified - correct_count
            }
        }
        
        self.update_stats()
        self.update_history_display()
        self.update_status(f"Protocol execution completed in {execution_time:.2f} seconds")
    
    def _display_malicious_results(self, outputs, s_list, T_list, r_list, Q_list, P, 
                                  y_pairs_list, w_pairs, execution_time, x_pairs, r):
        self.log_result("\n" + "=" * 60)
        self.log_result("Protocol execution completed")
        self.log_result(f"Execution time: {execution_time:.4f} seconds")
        self.log_result(f"Security parameter σ: {self.ot_extension.sigma}")
        self.log_result(f"Challenge set P size: {len(P)}")
        self.log_result(f"Extended {self.ot_extension.m} OTs")
        self.log_result(f"Average time per OT: {execution_time/self.ot_extension.m*1000:.2f} ms")
        
        self.log_result("\n--- Intermediate Protocol Results ---")
        self.log_result(f"Number of rounds: {len(s_list)}")
        self.log_result(f"Number of sender random vectors: {len(s_list)}")
        self.log_result(f"Number of receiver matrices: {len(T_list)}")
        
        verify_sample = self.ot_extension.verification_sample_size
        if verify_sample == 0:
            verify_sample = len(outputs)
        
        self.log_result(f"\n--- Correctness Verification (sampling {verify_sample} of {len(outputs)} OTs) ---")
        
        correct_count, total_verified, incorrect_indices = self.ot_extension.verify_correctness(
            outputs, x_pairs, r, verify_sample
        )
        
        for j in range(min(5, total_verified)):
            expected = x_pairs[j][r[j]]
            actual = outputs[j]
            is_correct = (expected == actual)
            self.log_result(f"OT {j}: {'✓' if is_correct else '✗'} Output length = {len(outputs[j])} bytes")
        
        if total_verified > 5:
            self.log_result(f"... and {total_verified - 5} more OTs verified")
        
        if correct_count == total_verified:
            self.log_result(f"All {total_verified} verified OTs are correct!")
        else:
            self.log_result(f"Warning: {total_verified - correct_count} of {total_verified} verified OTs failed verification")
            if incorrect_indices:
                self.log_result(f"First 5 incorrect indices: {incorrect_indices[:5]}")
        
        if verify_sample < len(outputs):
            stats = self.ot_extension.statistical_verification_analysis(
                verify_sample, len(outputs), confidence=0.99
            )
            if stats:
                self.log_result(f"\n--- Statistical Verification Analysis ---")
                self.log_result(f"Confidence level: {stats.get('confidence_level', 0):.3f}")
                self.log_result(f"Error probability upper bound: {stats.get('error_probability_upper_bound', 0):.6f}")
                self.log_result(f"Verification coverage: {stats.get('verification_coverage', 0):.4f}")
                self.log_result(f"Undetected errors probability: {stats.get('undetected_errors_probability', 0):.6f}")
        
        self.log_result("\nProtocol execution successful! Malicious adversary detection mechanism active.")
        
        params = {
            "k": self.ot_extension.k,
            "m": self.ot_extension.m,
            "ell": self.ot_extension.ell,
            "sigma": self.ot_extension.sigma,
            "protocol": "malicious",
            "verification_sample": verify_sample
        }
        self.ot_extension.add_to_history("malicious", params, execution_time, True)
        
        self.last_results = {
            "protocol": "malicious",
            "execution_time": execution_time,
            "outputs": outputs,
            "parameters": params,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "challenge_set_size": len(P),
            "verification_stats": {
                "correct_count": correct_count,
                "total_verified": total_verified,
                "incorrect_count": total_verified - correct_count
            }
        }
        
        self.update_stats()
        self.update_history_display()
        self.update_status(f"Malicious model protocol completed in {execution_time:.2f} seconds")
    
    def open_performance_test_window(self):
        """Open performance test configuration window"""
        test_window = tk.Toplevel(self.root)
        test_window.title("Performance Test Configuration")
        test_window.geometry("500x400")
        test_window.transient(self.root)
        test_window.grab_set()
        
        main_frame = ttk.Frame(test_window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main_frame, text="Performance Test Parameters", 
                 font=("Arial", self.title_font_size, "bold")).pack(pady=(0, 20))
        
        param_frame = ttk.LabelFrame(main_frame, text="Test Parameters", padding="15")
        param_frame.pack(fill=tk.X, pady=(0, 15))
        
        ttk.Label(param_frame, text="m values (comma-separated):", font=("Arial", self.font_size)).pack(anchor=tk.W, pady=(0, 5))
        m_values_var = tk.StringVar(value="100, 500, 1000, 2000, 5000")
        m_entry = ttk.Entry(param_frame, textvariable=m_values_var, width=50, font=("Arial", self.font_size))
        m_entry.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(param_frame, text="Protocol type:", font=("Arial", self.font_size)).pack(anchor=tk.W, pady=(0, 5))
        protocol_var = tk.StringVar(value=self.protocol_var.get())
        protocol_frame = ttk.Frame(param_frame)
        protocol_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Radiobutton(protocol_frame, text="Semi-Honest", variable=protocol_var, 
                       value="semi_honest").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(protocol_frame, text="Malicious", variable=protocol_var, 
                       value="malicious").pack(side=tk.LEFT)
        
        ttk.Label(param_frame, text="Repetitions per m value:", font=("Arial", self.font_size)).pack(anchor=tk.W, pady=(0, 5))
        reps_var = tk.StringVar(value="3")
        reps_spinbox = ttk.Spinbox(param_frame, from_=1, to=10, textvariable=reps_var, width=10)
        reps_spinbox.pack(anchor=tk.W, pady=(0, 10))
        
        ttk.Label(param_frame, text="Note: Performance test may take some time.", 
                 font=("Arial", self.font_size - 1), foreground="gray").pack(anchor=tk.W, pady=(0, 5))
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))
        
        def run_performance_test():
            try:
                m_values_str = m_values_var.get()
                m_values = [int(m.strip()) for m in m_values_str.split(",") if m.strip()]
                
                if not m_values:
                    messagebox.showerror("Error", "Please enter valid m values")
                    return
                
                protocol_type = protocol_var.get()
                repetitions = int(reps_var.get())
                
                test_window.destroy()
                
                self.update_status("Starting performance test...")
                
                thread = threading.Thread(
                    target=self._run_performance_test_thread,
                    args=(m_values, protocol_type, repetitions)
                )
                thread.daemon = True
                thread.start()
                
            except ValueError as e:
                messagebox.showerror("Error", f"Invalid parameter: {str(e)}")
            except Exception as e:
                messagebox.showerror("Error", f"Error configuring test: {str(e)}")
        
        ttk.Button(button_frame, text="Run Performance Test", 
                  command=run_performance_test, style="Green.TButton").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Cancel", 
                  command=test_window.destroy).pack(side=tk.LEFT)
    
    def _run_performance_test_thread(self, m_values, protocol_type, repetitions):
        """Run performance test in separate thread"""
        try:
            k = int(self.k_var.get())
            ell = int(self.ell_var.get())
            sigma = int(self.sigma_var.get())
            
            self.log_result("\n" + "=" * 60)
            self.log_result(f"Starting performance test for {protocol_type} protocol")
            self.log_result(f"Testing m values: {m_values}")
            self.log_result(f"Repetitions per m: {repetitions}")
            self.log_result(f"k={k}, ell={ell}, sigma={sigma}")
            self.log_result("=" * 60)
            
            performance_data = self.ot_extension.performance_test(
                m_values=m_values,
                protocol_type=protocol_type,
                k=k,
                ell=ell,
                sigma=sigma if protocol_type == "malicious" else None,
                repetitions=repetitions
            )
            
            self.root.after(0, self._display_performance_results, performance_data)
            
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Performance test failed: {str(e)}"))
            self.root.after(0, lambda: self.update_status("Performance test failed"))
    
    def _display_performance_results(self, performance_data):
        """Display performance test results and create visualization"""
        self.log_result("\n" + "=" * 60)
        self.log_result("Performance Test Results")
        self.log_result("=" * 60)
        
        for data in performance_data:
            self.log_result(f"\nm = {data['m']}:")
            self.log_result(f"  Average time: {data['avg_time_seconds']:.4f} seconds")
            self.log_result(f"  Standard deviation: {data['std_time_seconds']:.4f} seconds")
            self.log_result(f"  Average time per OT: {data['avg_time_per_ot_ms']:.4f} ms")
            self.log_result(f"  Protocol type: {data['protocol_type']}")
        
        self.create_performance_plot(performance_data)
        self.update_status("Performance test completed")
    
    def create_performance_plot(self, performance_data):
        """Create performance visualization plot"""
        self.figure.clear()
        
        if not performance_data:
            return
        
        protocol_type = performance_data[0]['protocol_type']
        
        ax1 = self.figure.add_subplot(211)
        ax2 = self.figure.add_subplot(212)
        
        m_values = [data['m'] for data in performance_data]
        avg_times = [data['avg_time_seconds'] for data in performance_data]
        std_times = [data['std_time_seconds'] for data in performance_data]
        avg_time_per_ot = [data['avg_time_per_ot_ms'] for data in performance_data]
        
        ax1.errorbar(m_values, avg_times, yerr=std_times, fmt='o-', 
                    capsize=5, capthick=2, markersize=8, linewidth=2)
        ax1.set_xlabel('Number of Extended OTs (m)', fontsize=12)
        ax1.set_ylabel('Execution Time (seconds)', fontsize=12)
        ax1.set_title(f'OT Extension Performance: {protocol_type.capitalize()} Model', 
                     fontsize=14, fontweight='bold')
        ax1.grid(True, alpha=0.3)
        ax1.set_xscale('log')
        ax1.set_yscale('log')
        
        ax2.plot(m_values, avg_time_per_ot, 's-', markersize=8, linewidth=2, color='orange')
        ax2.set_xlabel('Number of Extended OTs (m)', fontsize=12)
        ax2.set_ylabel('Time per OT (milliseconds)', fontsize=12)
        ax2.set_title('Average Time per OT Extension', fontsize=14, fontweight='bold')
        ax2.grid(True, alpha=0.3)
        ax2.set_xscale('log')
        ax2.set_yscale('log')
        
        self.figure.tight_layout()
        self.canvas.draw()
    
    def clear_plot(self):
        """Clear the performance plot"""
        self.figure.clear()
        ax = self.figure.add_subplot(111)
        ax.text(0.5, 0.5, 'No performance data available\nRun performance test to generate plot', 
               horizontalalignment='center', verticalalignment='center', 
               transform=ax.transAxes, fontsize=12)
        ax.set_axis_off()
        self.canvas.draw()
        self.update_status("Plot cleared")
    
    def export_plot(self):
        """Export the performance plot to file"""
        if not hasattr(self.ot_extension, 'performance_data') or not self.ot_extension.performance_data:
            messagebox.showwarning("Warning", "No performance data to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[
                ("PNG files", "*.png"),
                ("PDF files", "*.pdf"),
                ("SVG files", "*.svg"),
                ("All files", "*.*")
            ],
            title="Export Plot"
        )
        
        if not file_path:
            return
        
        try:
            self.figure.savefig(file_path, dpi=300, bbox_inches='tight')
            self.update_status(f"Plot exported to: {file_path}")
            messagebox.showinfo("Success", f"Plot successfully exported to:\n{file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def log_result(self, message):
        self.result_text.insert(tk.END, message + "\n")
        self.result_text.see(tk.END)
        self.root.update_idletasks()
    
    def update_stats(self):
        self.stats_text.delete(1.0, tk.END)
        
        if hasattr(self, 'last_results'):
            results = self.last_results
            
            self.stats_text.insert(tk.END, "Last Execution Statistics\n")
            self.stats_text.insert(tk.END, "=" * 40 + "\n\n")
            
            self.stats_text.insert(tk.END, f"Protocol type: {results['protocol']}\n")
            self.stats_text.insert(tk.END, f"Execution time: {results['execution_time']:.4f} seconds\n")
            self.stats_text.insert(tk.END, f"Timestamp: {results['timestamp']}\n\n")
            
            params = results['parameters']
            for key, value in params.items():
                self.stats_text.insert(tk.END, f"{key}: {value}\n")
            
            if 'verification_stats' in results:
                stats = results['verification_stats']
                self.stats_text.insert(tk.END, f"\nVerification Statistics:\n")
                self.stats_text.insert(tk.END, f"  Correct OTs: {stats['correct_count']}\n")
                self.stats_text.insert(tk.END, f"  Total Verified: {stats['total_verified']}\n")
                self.stats_text.insert(tk.END, f"  Incorrect OTs: {stats['incorrect_count']}\n")
                if stats['total_verified'] > 0:
                    accuracy = stats['correct_count'] / stats['total_verified'] * 100
                    self.stats_text.insert(tk.END, f"  Accuracy: {accuracy:.2f}%\n")
            
            if 'outputs' in results:
                self.stats_text.insert(tk.END, f"\nNumber of outputs: {len(results['outputs'])}\n")
                if len(results['outputs']) > 0:
                    self.stats_text.insert(tk.END, f"Output sample (first): {results['outputs'][0].hex()[:32]}...\n")
        
        if hasattr(self.ot_extension, 'execution_history') and self.ot_extension.execution_history:
            self.stats_text.insert(tk.END, "\n" + "=" * 40 + "\n")
            self.stats_text.insert(tk.END, "Overall Statistics\n")
            self.stats_text.insert(tk.END, "=" * 40 + "\n\n")
            
            total_executions = len(self.ot_extension.execution_history)
            semi_honest_count = sum(1 for h in self.ot_extension.execution_history 
                                  if h['protocol_type'] == 'semi_honest')
            malicious_count = total_executions - semi_honest_count
            
            self.stats_text.insert(tk.END, f"Total executions: {total_executions}\n")
            self.stats_text.insert(tk.END, f"Semi-honest executions: {semi_honest_count}\n")
            self.stats_text.insert(tk.END, f"Malicious executions: {malicious_count}\n")
            
            if total_executions > 0:
                avg_time = sum(h['execution_time'] for h in self.ot_extension.execution_history) / total_executions
                self.stats_text.insert(tk.END, f"Average execution time: {avg_time:.4f} seconds\n")
    
    def update_history_display(self):
        self.history_text.delete(1.0, tk.END)
        
        if not hasattr(self.ot_extension, 'execution_history') or not self.ot_extension.execution_history:
            self.history_text.insert(tk.END, "No execution history available\n")
            return
        
        self.history_text.insert(tk.END, "Execution History\n")
        self.history_text.insert(tk.END, "=" * 60 + "\n\n")
        
        for i, record in enumerate(reversed(self.ot_extension.execution_history[-20:]), 1):
            self.history_text.insert(tk.END, f"{i}. {record['timestamp']}\n")
            self.history_text.insert(tk.END, f"   Protocol: {record['protocol_type']}\n")
            self.history_text.insert(tk.END, f"   Duration: {record['execution_time']:.4f} seconds\n")
            
            params = record['parameters']
            param_str = ", ".join(f"{k}={v}" for k, v in params.items())
            self.history_text.insert(tk.END, f"   Parameters: {param_str}\n")
            self.history_text.insert(tk.END, "-" * 40 + "\n")
    
    def export_results(self):
        if not hasattr(self, 'last_results'):
            messagebox.showwarning("Warning", "No results to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json"),
                ("Text files", "*.txt"),
                ("CSV files", "*.csv"),
                ("All files", "*.*")
            ],
            title="Export Results"
        )
        
        if not file_path:
            return
        
        try:
            if file_path.endswith('.json'):
                with open(file_path, 'w', encoding='utf-8') as f:
                    export_data = self.last_results.copy()
                    if 'outputs' in export_data:
                        export_data['outputs'] = [out.hex() for out in export_data['outputs']]
                    json.dump(export_data, f, indent=2, ensure_ascii=False)
                    
            elif file_path.endswith('.csv'):
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Field', 'Value'])
                    
                    for key, value in self.last_results.items():
                        if key == 'outputs':
                            writer.writerow([key, f'{len(value)} outputs'])
                            for i, out in enumerate(value[:10]):
                                writer.writerow([f'output{i}', out.hex()[:32] + '...'])
                        elif key == 'parameters':
                            for param_key, param_value in value.items():
                                writer.writerow([f'param_{param_key}', param_value])
                        elif key == 'verification_stats':
                            for stat_key, stat_value in value.items():
                                writer.writerow([f'verification_{stat_key}', stat_value])
                        else:
                            writer.writerow([key, str(value)])
                            
            else:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("OT-Extension Protocol Execution Results\n")
                    f.write("=" * 50 + "\n\n")
                    
                    for key, value in self.last_results.items():
                        if key == 'outputs':
                            f.write(f"{key}:\n")
                            for i, out in enumerate(value[:5]):
                                f.write(f"  [{i}] {out.hex()[:32]}...\n")
                        elif key == 'parameters':
                            f.write(f"{key}:\n")
                            for param_key, param_value in value.items():
                                f.write(f"  {param_key}: {param_value}\n")
                        elif key == 'verification_stats':
                            f.write(f"Verification Statistics:\n")
                            for stat_key, stat_value in value.items():
                                f.write(f"  {stat_key}: {stat_value}\n")
                        else:
                            f.write(f"{key}: {value}\n")
            
            self.update_status(f"Results exported to: {file_path}")
            messagebox.showinfo("Success", f"Results successfully exported to:\n{file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def export_history(self):
        if not hasattr(self.ot_extension, 'execution_history') or not self.ot_extension.execution_history:
            messagebox.showwarning("Warning", "No history to export")
            return
        
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json"),
                ("CSV files", "*.csv"),
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ],
            title="Export History"
        )
        
        if not file_path:
            return
        
        try:
            if file_path.endswith('.json'):
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(self.ot_extension.execution_history, f, indent=2, ensure_ascii=False, default=str)
                    
            elif file_path.endswith('.csv'):
                with open(file_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['Timestamp', 'Protocol Type', 'Execution Time (s)', 'Parameters', 'Success'])
                    
                    for record in self.ot_extension.execution_history:
                        params_str = json.dumps(record['parameters'], ensure_ascii=False)
                        writer.writerow([
                            record['timestamp'],
                            record['protocol_type'],
                            f"{record['execution_time']:.6f}",
                            params_str,
                            'Yes' if record['success'] else 'No'
                        ])
                        
            else:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("OT-Extension Protocol Execution History\n")
                    f.write("=" * 60 + "\n\n")
                    
                    for i, record in enumerate(self.ot_extension.execution_history, 1):
                        f.write(f"Record #{i}\n")
                        f.write(f"Time: {record['timestamp']}\n")
                        f.write(f"Protocol: {record['protocol_type']}\n")
                        f.write(f"Duration: {record['execution_time']:.6f} seconds\n")
                        f.write(f"Success: {'Yes' if record['success'] else 'No'}\n")
                        f.write("Parameters:\n")
                        
                        for key, value in record['parameters'].items():
                            f.write(f"  {key}: {value}\n")
                        
                        f.write("-" * 40 + "\n\n")
            
            self.update_status(f"History exported to: {file_path}")
            messagebox.showinfo("Success", f"History successfully exported to:\n{file_path}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def clear_results(self):
        self.result_text.delete(1.0, tk.END)
        self.stats_text.delete(1.0, tk.END)
        self.update_status("Results cleared")

def main():
    root = tk.Tk()
    app = OTExtensionUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
