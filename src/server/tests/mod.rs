pub mod basic;
pub mod phase3_perf;
pub mod phase5_integration;

// 简单的测试辅助函数
pub fn create_simple_test_data() -> Vec<i32> {
    vec![1, 2, 3, 4, 5]
}

pub fn add_numbers(a: i32, b: i32) -> i32 {
    a + b
}
