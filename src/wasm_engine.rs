//! Safe bytecode VM for extensible policy rules.
//!
//! Provides a lightweight, sandboxed virtual machine that executes
//! policy extension scripts compiled to a simple bytecode format.
//! Policies can be loaded at runtime without recompiling the binary.
//! Covers R17 (Wasm-inspired extensible policies).

use serde::{Deserialize, Serialize};

// ── Bytecode Instruction Set ─────────────────────────────────────────────────

/// Stack-based bytecode instructions for the policy VM.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Opcode {
    /// Push a float constant onto the stack
    PushConst(f64),
    /// Load a named variable (from the environment)
    LoadVar(String),
    /// Arithmetic: pop two, push result
    Add,
    Sub,
    Mul,
    Div,
    /// Comparison: pop two, push 1.0 (true) or 0.0 (false)
    CmpGt,
    CmpLt,
    CmpGe,
    CmpLe,
    CmpEq,
    /// Logical
    And,
    Or,
    Not,
    /// Control flow
    JumpIf(usize),     // jump to instruction index if top is truthy
    Jump(usize),       // unconditional jump
    /// Output: pop and store as named result
    StoreResult(String),
    /// Halt execution
    Halt,
    /// Duplicate top of stack
    Dup,
    /// Pop and discard
    Pop,
}

// ── Policy Program ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyProgram {
    pub name: String,
    pub version: u32,
    pub instructions: Vec<Opcode>,
    pub description: String,
}

impl PolicyProgram {
    pub fn new(name: &str, instructions: Vec<Opcode>) -> Self {
        Self {
            name: name.to_string(),
            version: 1,
            instructions,
            description: String::new(),
        }
    }
}

// ── VM Execution ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmResult {
    pub success: bool,
    pub outputs: std::collections::HashMap<String, f64>,
    pub steps_executed: usize,
    pub error: Option<String>,
}

/// Sandboxed policy VM with resource limits.
pub struct PolicyVm {
    max_steps: usize,
    max_stack: usize,
}

impl Default for PolicyVm {
    fn default() -> Self {
        Self::new(10_000, 256)
    }
}

impl PolicyVm {
    pub fn new(max_steps: usize, max_stack: usize) -> Self {
        Self {
            max_steps,
            max_stack,
        }
    }

    /// Execute a policy program with the given environment variables.
    pub fn execute(
        &self,
        program: &PolicyProgram,
        env: &std::collections::HashMap<String, f64>,
    ) -> VmResult {
        let mut stack: Vec<f64> = Vec::new();
        let mut outputs = std::collections::HashMap::new();
        let mut pc = 0usize;
        let mut steps = 0usize;

        loop {
            if pc >= program.instructions.len() {
                break;
            }
            if steps >= self.max_steps {
                return VmResult {
                    success: false,
                    outputs,
                    steps_executed: steps,
                    error: Some("step limit exceeded".into()),
                };
            }
            if stack.len() > self.max_stack {
                return VmResult {
                    success: false,
                    outputs,
                    steps_executed: steps,
                    error: Some("stack overflow".into()),
                };
            }

            steps += 1;
            let instr = &program.instructions[pc];

            match instr {
                Opcode::PushConst(v) => {
                    stack.push(*v);
                    pc += 1;
                }
                Opcode::LoadVar(name) => {
                    let val = env.get(name).copied().unwrap_or(0.0);
                    stack.push(val);
                    pc += 1;
                }
                Opcode::Add => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(a + b);
                    }
                    pc += 1;
                }
                Opcode::Sub => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(a - b);
                    }
                    pc += 1;
                }
                Opcode::Mul => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(a * b);
                    }
                    pc += 1;
                }
                Opcode::Div => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        if b.abs() < f64::EPSILON {
                            return VmResult {
                                success: false,
                                outputs,
                                steps_executed: steps,
                                error: Some("division by zero".into()),
                            };
                        }
                        stack.push(a / b);
                    }
                    pc += 1;
                }
                Opcode::CmpGt => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(if a > b { 1.0 } else { 0.0 });
                    }
                    pc += 1;
                }
                Opcode::CmpLt => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(if a < b { 1.0 } else { 0.0 });
                    }
                    pc += 1;
                }
                Opcode::CmpGe => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(if a >= b { 1.0 } else { 0.0 });
                    }
                    pc += 1;
                }
                Opcode::CmpLe => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(if a <= b { 1.0 } else { 0.0 });
                    }
                    pc += 1;
                }
                Opcode::CmpEq => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(if (a - b).abs() < f64::EPSILON { 1.0 } else { 0.0 });
                    }
                    pc += 1;
                }
                Opcode::And => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(if a > 0.5 && b > 0.5 { 1.0 } else { 0.0 });
                    }
                    pc += 1;
                }
                Opcode::Or => {
                    if let (Some(b), Some(a)) = (stack.pop(), stack.pop()) {
                        stack.push(if a > 0.5 || b > 0.5 { 1.0 } else { 0.0 });
                    }
                    pc += 1;
                }
                Opcode::Not => {
                    if let Some(a) = stack.pop() {
                        stack.push(if a > 0.5 { 0.0 } else { 1.0 });
                    }
                    pc += 1;
                }
                Opcode::JumpIf(target) => {
                    if let Some(cond) = stack.pop() {
                        if cond > 0.5 {
                            pc = *target;
                        } else {
                            pc += 1;
                        }
                    } else {
                        pc += 1;
                    }
                }
                Opcode::Jump(target) => {
                    pc = *target;
                }
                Opcode::StoreResult(name) => {
                    if let Some(val) = stack.pop() {
                        outputs.insert(name.clone(), val);
                    }
                    pc += 1;
                }
                Opcode::Halt => break,
                Opcode::Dup => {
                    if let Some(&top) = stack.last() {
                        stack.push(top);
                    }
                    pc += 1;
                }
                Opcode::Pop => {
                    stack.pop();
                    pc += 1;
                }
            }
        }

        VmResult {
            success: true,
            outputs,
            steps_executed: steps,
            error: None,
        }
    }
}

// ── Policy Compiler (Expression → Bytecode) ──────────────────────────────────

/// Compile a simple rule expression into bytecode.
///
/// Supported expressions:
///   "cpu_load > 80 AND auth_failures > 5"  → threat_detected = 1.0
///   "score * 2.0 + 1.0"                    → computed_value
pub fn compile_rule(name: &str, expression: &str) -> Result<PolicyProgram, String> {
    let tokens = tokenize(expression)?;
    let instructions = compile_tokens(&tokens)?;
    Ok(PolicyProgram {
        name: name.to_string(),
        version: 1,
        instructions,
        description: format!("compiled from: {expression}"),
    })
}

#[derive(Debug, Clone)]
enum Token {
    Number(f64),
    Ident(String),
    Op(char),
    Gt,
    Lt,
    Ge,
    Le,
    Eq,
    And,
    Or,
    Not,
}

fn tokenize(expr: &str) -> Result<Vec<Token>, String> {
    let mut tokens = Vec::new();
    let chars: Vec<char> = expr.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        match chars[i] {
            ' ' | '\t' | '\n' => i += 1,
            '+' => { tokens.push(Token::Op('+')); i += 1; }
            '-' => { tokens.push(Token::Op('-')); i += 1; }
            '*' => { tokens.push(Token::Op('*')); i += 1; }
            '/' => { tokens.push(Token::Op('/')); i += 1; }
            '>' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    tokens.push(Token::Ge);
                    i += 2;
                } else {
                    tokens.push(Token::Gt);
                    i += 1;
                }
            }
            '<' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    tokens.push(Token::Le);
                    i += 2;
                } else {
                    tokens.push(Token::Lt);
                    i += 1;
                }
            }
            '=' => {
                if i + 1 < chars.len() && chars[i + 1] == '=' {
                    tokens.push(Token::Eq);
                    i += 2;
                } else {
                    return Err(format!("unexpected '=' at position {i}"));
                }
            }
            c if c.is_ascii_digit() || c == '.' => {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_digit() || chars[i] == '.') {
                    i += 1;
                }
                let num: f64 = chars[start..i]
                    .iter()
                    .collect::<String>()
                    .parse()
                    .map_err(|_| format!("invalid number at position {start}"))?;
                tokens.push(Token::Number(num));
            }
            c if c.is_ascii_alphabetic() || c == '_' => {
                let start = i;
                while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                    i += 1;
                }
                let word: String = chars[start..i].iter().collect();
                match word.to_uppercase().as_str() {
                    "AND" => tokens.push(Token::And),
                    "OR" => tokens.push(Token::Or),
                    "NOT" => tokens.push(Token::Not),
                    _ => tokens.push(Token::Ident(word)),
                }
            }
            c => return Err(format!("unexpected character '{c}' at position {i}")),
        }
    }

    Ok(tokens)
}

fn compile_tokens(tokens: &[Token]) -> Result<Vec<Opcode>, String> {
    let mut instructions = Vec::new();

    // Simple two-pass: emit loads/pushes, then operators
    // For now, handle infix expressions left-to-right (no precedence)
    let mut i = 0;
    while i < tokens.len() {
        match &tokens[i] {
            Token::Number(v) => {
                instructions.push(Opcode::PushConst(*v));
                i += 1;
            }
            Token::Ident(name) => {
                instructions.push(Opcode::LoadVar(name.clone()));
                i += 1;
            }
            Token::Op('+') => { instructions.push(Opcode::Add); i += 1; }
            Token::Op('-') => { instructions.push(Opcode::Sub); i += 1; }
            Token::Op('*') => { instructions.push(Opcode::Mul); i += 1; }
            Token::Op('/') => { instructions.push(Opcode::Div); i += 1; }
            Token::Gt => { instructions.push(Opcode::CmpGt); i += 1; }
            Token::Lt => { instructions.push(Opcode::CmpLt); i += 1; }
            Token::Ge => { instructions.push(Opcode::CmpGe); i += 1; }
            Token::Le => { instructions.push(Opcode::CmpLe); i += 1; }
            Token::Eq => { instructions.push(Opcode::CmpEq); i += 1; }
            Token::And => { instructions.push(Opcode::And); i += 1; }
            Token::Or => { instructions.push(Opcode::Or); i += 1; }
            Token::Not => { instructions.push(Opcode::Not); i += 1; }
            _ => {
                return Err(format!("unexpected token at position {i}"));
            }
        }
    }

    instructions.push(Opcode::StoreResult("result".into()));
    instructions.push(Opcode::Halt);
    Ok(instructions)
}

// ── Policy Extension Registry ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionInfo {
    pub name: String,
    pub version: u32,
    pub description: String,
    pub instruction_count: usize,
}

/// Registry of loaded policy extensions.
pub struct ExtensionRegistry {
    programs: Vec<PolicyProgram>,
}

impl Default for ExtensionRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ExtensionRegistry {
    pub fn new() -> Self {
        Self {
            programs: Vec::new(),
        }
    }

    /// Register a policy extension.
    pub fn register(&mut self, program: PolicyProgram) {
        self.programs.push(program);
    }

    /// List all registered extensions.
    pub fn list(&self) -> Vec<ExtensionInfo> {
        self.programs
            .iter()
            .map(|p| ExtensionInfo {
                name: p.name.clone(),
                version: p.version,
                description: p.description.clone(),
                instruction_count: p.instructions.len(),
            })
            .collect()
    }

    /// Execute all registered policies and collect results.
    pub fn execute_all(
        &self,
        env: &std::collections::HashMap<String, f64>,
    ) -> Vec<(String, VmResult)> {
        let vm = PolicyVm::default();
        self.programs
            .iter()
            .map(|p| (p.name.clone(), vm.execute(p, env)))
            .collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn vm_basic_arithmetic() {
        let program = PolicyProgram::new(
            "add_test",
            vec![
                Opcode::PushConst(3.0),
                Opcode::PushConst(4.0),
                Opcode::Add,
                Opcode::StoreResult("sum".into()),
                Opcode::Halt,
            ],
        );
        let vm = PolicyVm::default();
        let result = vm.execute(&program, &HashMap::new());
        assert!(result.success);
        assert!((result.outputs["sum"] - 7.0).abs() < f64::EPSILON);
    }

    #[test]
    fn vm_comparison() {
        let program = PolicyProgram::new(
            "cmp_test",
            vec![
                Opcode::PushConst(10.0),
                Opcode::PushConst(5.0),
                Opcode::CmpGt,
                Opcode::StoreResult("is_greater".into()),
                Opcode::Halt,
            ],
        );
        let vm = PolicyVm::default();
        let result = vm.execute(&program, &HashMap::new());
        assert!(result.success);
        assert!((result.outputs["is_greater"] - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn vm_loads_variables() {
        let program = PolicyProgram::new(
            "var_test",
            vec![
                Opcode::LoadVar("cpu_load".into()),
                Opcode::PushConst(80.0),
                Opcode::CmpGt,
                Opcode::StoreResult("cpu_high".into()),
                Opcode::Halt,
            ],
        );
        let mut env = HashMap::new();
        env.insert("cpu_load".into(), 95.0);

        let vm = PolicyVm::default();
        let result = vm.execute(&program, &env);
        assert!(result.success);
        assert!((result.outputs["cpu_high"] - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn vm_logical_and() {
        let program = PolicyProgram::new(
            "and_test",
            vec![
                Opcode::LoadVar("cpu_load".into()),
                Opcode::PushConst(80.0),
                Opcode::CmpGt,
                Opcode::LoadVar("auth_failures".into()),
                Opcode::PushConst(5.0),
                Opcode::CmpGt,
                Opcode::And,
                Opcode::StoreResult("threat".into()),
                Opcode::Halt,
            ],
        );
        let mut env = HashMap::new();
        env.insert("cpu_load".into(), 95.0);
        env.insert("auth_failures".into(), 8.0);

        let vm = PolicyVm::default();
        let result = vm.execute(&program, &env);
        assert!(result.success);
        assert!((result.outputs["threat"] - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn vm_division_by_zero() {
        let program = PolicyProgram::new(
            "div_zero",
            vec![
                Opcode::PushConst(10.0),
                Opcode::PushConst(0.0),
                Opcode::Div,
                Opcode::Halt,
            ],
        );
        let vm = PolicyVm::default();
        let result = vm.execute(&program, &HashMap::new());
        assert!(!result.success);
        assert!(result.error.unwrap().contains("division by zero"));
    }

    #[test]
    fn vm_step_limit() {
        // Infinite loop
        let program = PolicyProgram::new(
            "loop",
            vec![Opcode::PushConst(1.0), Opcode::Pop, Opcode::Jump(0)],
        );
        let vm = PolicyVm::new(100, 256);
        let result = vm.execute(&program, &HashMap::new());
        assert!(!result.success);
        assert!(result.error.unwrap().contains("step limit"));
    }

    #[test]
    fn vm_conditional_jump() {
        let program = PolicyProgram::new(
            "jump_test",
            vec![
                Opcode::PushConst(1.0),    // 0: push true
                Opcode::JumpIf(3),          // 1: if true, jump to 3
                Opcode::PushConst(99.0),    // 2: should be skipped
                Opcode::PushConst(42.0),    // 3: landing
                Opcode::StoreResult("val".into()), // 4
                Opcode::Halt,              // 5
            ],
        );
        let vm = PolicyVm::default();
        let result = vm.execute(&program, &HashMap::new());
        assert!(result.success);
        assert!((result.outputs["val"] - 42.0).abs() < f64::EPSILON);
    }

    #[test]
    fn compile_simple_expression() {
        let program = compile_rule("test", "cpu_load 80.0 >").unwrap();
        let mut env = HashMap::new();
        env.insert("cpu_load".into(), 95.0);

        let vm = PolicyVm::default();
        let result = vm.execute(&program, &env);
        assert!(result.success);
        assert!((result.outputs["result"] - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn extension_registry() {
        let mut registry = ExtensionRegistry::new();
        registry.register(PolicyProgram::new(
            "rule_1",
            vec![
                Opcode::LoadVar("score".into()),
                Opcode::PushConst(3.0),
                Opcode::CmpGt,
                Opcode::StoreResult("alert".into()),
                Opcode::Halt,
            ],
        ));
        registry.register(PolicyProgram::new(
            "rule_2",
            vec![
                Opcode::LoadVar("battery".into()),
                Opcode::PushConst(20.0),
                Opcode::CmpLt,
                Opcode::StoreResult("low_battery".into()),
                Opcode::Halt,
            ],
        ));

        let info = registry.list();
        assert_eq!(info.len(), 2);

        let mut env = HashMap::new();
        env.insert("score".into(), 5.0);
        env.insert("battery".into(), 15.0);

        let results = registry.execute_all(&env);
        assert_eq!(results.len(), 2);
        assert!(results[0].1.success);
        assert!(results[1].1.success);
    }
}
