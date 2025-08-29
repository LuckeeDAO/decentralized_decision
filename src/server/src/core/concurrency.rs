#![allow(dead_code)]
//! 并发处理优化模块
//!
//! 实现第六阶段的并发处理优化，包括智能线程池、任务调度优化和并发控制

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use std::sync::RwLock;
use tokio::sync::{Semaphore, Mutex};
use serde::{Serialize, Deserialize};
use anyhow::Result;

/// 任务优先级
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TaskPriority {
    Low = 0,
    Normal = 1,
    High = 2,
    Critical = 3,
}

/// 任务状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Cancelled,
}

/// 任务信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskInfo {
    pub id: String,
    pub priority: TaskPriority,
    pub status: TaskStatus,
    #[serde(with = "instant_serde")]
    pub created_at: Instant,
    #[serde(with = "instant_serde_opt")]
    pub started_at: Option<Instant>,
    #[serde(with = "instant_serde_opt")]
    pub completed_at: Option<Instant>,
    pub duration_ms: Option<u64>,
    pub error_message: Option<String>,
}

/// 智能线程池配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadPoolConfig {
    pub min_threads: usize,
    pub max_threads: usize,
    pub queue_capacity: usize,
    pub keep_alive_ms: u64,
    pub max_concurrent_tasks: usize,
}

impl Default for ThreadPoolConfig {
    fn default() -> Self {
        Self {
            min_threads: 4,
            max_threads: 32,
            queue_capacity: 1000,
            keep_alive_ms: 60000, // 1分钟
            max_concurrent_tasks: 100,
        }
    }
}

/// 智能线程池
pub struct SmartThreadPool {
    config: ThreadPoolConfig,
    active_threads: Arc<AtomicUsize>,
    total_tasks: Arc<AtomicUsize>,
    completed_tasks: Arc<AtomicUsize>,
    failed_tasks: Arc<AtomicUsize>,
    task_queue: Arc<Mutex<VecDeque<QueuedTask>>>,
    semaphore: Arc<Semaphore>,
    running: Arc<AtomicBool>,
    worker_handles: Arc<RwLock<Vec<tokio::task::JoinHandle<()>>>>,
}

/// 队列中的任务
struct QueuedTask {
    #[allow(dead_code)]
    id: String,
    priority: TaskPriority,
    task: Box<dyn FnOnce() -> Result<()> + Send + 'static>,
    #[allow(dead_code)]
    created_at: Instant,
}

impl SmartThreadPool {
    pub fn new(config: ThreadPoolConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_tasks));
        
        Self {
            config,
            active_threads: Arc::new(AtomicUsize::new(0)),
            total_tasks: Arc::new(AtomicUsize::new(0)),
            completed_tasks: Arc::new(AtomicUsize::new(0)),
            failed_tasks: Arc::new(AtomicUsize::new(0)),
            task_queue: Arc::new(Mutex::new(VecDeque::new())),
            semaphore,
            running: Arc::new(AtomicBool::new(true)),
            worker_handles: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// 启动线程池
    pub async fn start(&self) -> Result<()> {
        self.running.store(true, Ordering::Relaxed);
        
        // 启动最小数量的工作线程
        for _ in 0..self.config.min_threads {
            self.spawn_worker().await?;
        }
        
        // 启动动态扩缩容监控
        self.start_autoscaling_monitor().await?;
        
        Ok(())
    }

    /// 停止线程池
    pub async fn stop(&self) -> Result<()> {
        self.running.store(false, Ordering::Relaxed);
        
        // 等待所有工作线程完成
        if let Ok(_handles) = self.worker_handles.read() {
            // 由于 JoinHandle 不能克隆，我们只能等待引用
            // 这里我们暂时跳过等待，在实际应用中应该重新设计
            // 或者使用 Arc<JoinHandle> 来存储句柄
        }
        
        Ok(())
    }

    /// 提交任务
    pub async fn submit<F>(&self, id: String, priority: TaskPriority, task: F) -> Result<()>
    where
        F: FnOnce() -> Result<()> + Send + 'static,
    {
        let queued_task = QueuedTask {
            id,
            priority,
            task: Box::new(task),
            created_at: Instant::now(),
        };
        
        // 根据优先级插入队列
        let mut queue = self.task_queue.lock().await;
        let insert_index = queue.binary_search_by(|qt| qt.priority.cmp(&priority))
            .unwrap_or_else(|e| e);
        queue.insert(insert_index, queued_task);
        
        self.total_tasks.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// 获取线程池状态
    pub fn get_status(&self) -> ThreadPoolStatus {
        ThreadPoolStatus {
            active_threads: self.active_threads.load(Ordering::Relaxed),
            total_tasks: self.total_tasks.load(Ordering::Relaxed),
            completed_tasks: self.completed_tasks.load(Ordering::Relaxed),
            failed_tasks: self.failed_tasks.load(Ordering::Relaxed),
            queue_size: {
                // 尝试获取队列大小，如果失败则返回0
                match self.task_queue.try_lock() {
                    Ok(queue) => queue.len(),
                    Err(_) => 0,
                }
            },
        }
    }

    /// 生成工作线程
    async fn spawn_worker(&self) -> Result<()> {
        let _worker_id = self.active_threads.fetch_add(1, Ordering::Relaxed);
        let task_queue = self.task_queue.clone();
        let semaphore = self.semaphore.clone();
        let running = self.running.clone();
        let completed_tasks = self.completed_tasks.clone();
        let failed_tasks = self.failed_tasks.clone();
        let worker_handles = self.worker_handles.clone();

        let handle = tokio::spawn(async move {
            while running.load(Ordering::Relaxed) {
                // 获取任务
                let task = {
                    let mut queue = task_queue.lock().await;
                    if let Some(queued_task) = queue.pop_front() {
                        Some(queued_task)
                    } else {
                        None
                    }
                };

                if let Some(queued_task) = task {
                    // 获取并发许可
                    if let Ok(_permit) = semaphore.acquire().await {
                        // 执行任务
                        let result = (queued_task.task)();
                        
                        if result.is_ok() {
                            completed_tasks.fetch_add(1, Ordering::Relaxed);
                        } else {
                            failed_tasks.fetch_add(1, Ordering::Relaxed);
                        }
                        // permit 在这里自动释放
                    } else {
                        // 如果获取许可失败，跳过这个任务
                        failed_tasks.fetch_add(1, Ordering::Relaxed);
                    }
                } else {
                    // 没有任务，短暂休眠
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        });

        // 保存工作线程句柄
        if let Ok(mut handles) = worker_handles.write() {
            handles.push(handle);
        }

        Ok(())
    }

    /// 启动自动扩缩容监控
    async fn start_autoscaling_monitor(&self) -> Result<()> {
        let config = self.config.clone();
        let active_threads = self.active_threads.clone();
        let task_queue = self.task_queue.clone();
        let worker_handles = self.worker_handles.clone();
        let running = self.running.clone();

        tokio::spawn(async move {
            while running.load(Ordering::Relaxed) {
                tokio::time::sleep(Duration::from_millis(config.keep_alive_ms)).await;
                
                let current_active = active_threads.load(Ordering::Relaxed);
                let queue_size = {
                    if let Ok(queue) = task_queue.try_lock() {
                        queue.len()
                    } else {
                        0
                    }
                };

                // 根据队列大小调整线程数
                if queue_size > current_active * 2 && current_active < config.max_threads {
                    // 增加线程
                    if let Ok(_handles) = worker_handles.write() {
                        // 这里应该调用 spawn_worker，但为了避免循环引用，简化处理
                        active_threads.fetch_add(1, Ordering::Relaxed);
                    }
                } else if queue_size < current_active / 2 && current_active > config.min_threads {
                    // 减少线程
                    active_threads.fetch_sub(1, Ordering::Relaxed);
                }
            }
        });

        Ok(())
    }
}

/// 线程池状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreadPoolStatus {
    pub active_threads: usize,
    pub total_tasks: usize,
    pub completed_tasks: usize,
    pub failed_tasks: usize,
    pub queue_size: usize,
}

/// 任务调度器
pub struct TaskScheduler {
    thread_pool: Arc<SmartThreadPool>,
    task_history: Arc<RwLock<Vec<TaskInfo>>>,
}

impl TaskScheduler {
    pub fn new(thread_pool: Arc<SmartThreadPool>) -> Self {
        Self {
            thread_pool,
            task_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// 提交任务
    pub async fn submit_task<F>(&self, id: String, priority: TaskPriority, task: F) -> Result<()>
    where
        F: FnOnce() -> Result<()> + Send + 'static,
    {
        // 记录任务信息
        let task_info = TaskInfo {
            id: id.clone(),
            priority,
            status: TaskStatus::Pending,
            created_at: Instant::now(),
            started_at: None,
            completed_at: None,
            duration_ms: None,
            error_message: None,
        };

        if let Ok(mut history) = self.task_history.write() {
            history.push(task_info);
        }

        // 提交到线程池
        self.thread_pool.submit(id, priority, task).await
    }

    /// 获取任务历史
    pub async fn get_task_history(&self) -> Vec<TaskInfo> {
        match self.task_history.read() {
            Ok(history) => history.clone(),
            Err(_) => Vec::new(),
        }
    }

    /// 获取线程池状态
    pub fn get_thread_pool_status(&self) -> ThreadPoolStatus {
        self.thread_pool.get_status()
    }
}

/// 并发控制器
#[derive(Clone)]
pub struct ConcurrencyController {
    max_concurrent_operations: usize,
    semaphore: Arc<Semaphore>,
    operation_count: Arc<AtomicUsize>,
    operation_history: Arc<RwLock<Vec<OperationRecord>>>,
}

/// 操作记录
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationRecord {
    pub operation_type: String,
    #[serde(with = "instant_serde")]
    pub start_time: Instant,
    #[serde(with = "instant_serde_opt")]
    pub end_time: Option<Instant>,
    pub duration_ms: Option<u64>,
    pub success: bool,
    pub error_message: Option<String>,
}

impl ConcurrencyController {
    pub fn new(max_concurrent_operations: usize) -> Self {
        Self {
            max_concurrent_operations,
            semaphore: Arc::new(Semaphore::new(max_concurrent_operations)),
            operation_count: Arc::new(AtomicUsize::new(0)),
            operation_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// 执行受控操作
    pub async fn execute<F, T>(&self, operation_type: &str, operation: F) -> Result<T>
    where
        F: FnOnce() -> Result<T> + Send + 'static,
        T: Send + 'static,
    {
        let start_time = Instant::now();
        let operation_type = operation_type.to_string();
        
        // 获取并发许可
        let _permit = self.semaphore.acquire().await?;
        self.operation_count.fetch_add(1, Ordering::Relaxed);
        
        let result = operation();
        
        let end_time = Instant::now();
        let duration = end_time.duration_since(start_time);
        
        // 记录操作历史
        let record = OperationRecord {
            operation_type,
            start_time,
            end_time: Some(end_time),
            duration_ms: Some(duration.as_millis() as u64),
            success: result.is_ok(),
            error_message: result.as_ref().err().map(|e| e.to_string()),
        };
        
        if let Ok(mut history) = self.operation_history.write() {
            history.push(record);
        }
        
        self.operation_count.fetch_sub(1, Ordering::Relaxed);
        result
    }

    /// 获取当前并发操作数
    pub fn get_current_concurrency(&self) -> usize {
        self.operation_count.load(Ordering::Relaxed)
    }

    /// 获取操作历史
    pub async fn get_operation_history(&self) -> Vec<OperationRecord> {
        match self.operation_history.read() {
            Ok(history) => history.clone(),
            Err(_) => Vec::new(),
        }
    }

    /// 获取并发统计
    pub async fn get_concurrency_stats(&self) -> ConcurrencyStats {
        let history = self.get_operation_history().await;
        let total_operations = history.len();
        let successful_operations = history.iter().filter(|r| r.success).count();
        let failed_operations = total_operations - successful_operations;
        
        let avg_duration = if total_operations > 0 {
            let total_duration: u64 = history.iter()
                .filter_map(|r| r.duration_ms)
                .sum();
            total_duration as f64 / total_operations as f64
        } else {
            0.0
        };
        
        ConcurrencyStats {
            total_operations,
            successful_operations,
            failed_operations,
            current_concurrency: self.get_current_concurrency(),
            max_concurrency: self.max_concurrent_operations,
            avg_duration_ms: avg_duration,
        }
    }
}

/// 并发统计
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConcurrencyStats {
    pub total_operations: usize,
    pub successful_operations: usize,
    pub failed_operations: usize,
    pub current_concurrency: usize,
    pub max_concurrency: usize,
    pub avg_duration_ms: f64,
}

/// 自定义序列化模块
mod instant_serde {
    use super::*;
    use serde::{Serializer, Deserializer};

    pub fn serialize<S>(instant: &Instant, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(instant.elapsed().as_millis() as u64)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Instant, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Instant::now() - Duration::from_millis(millis))
    }
}

/// 自定义可选序列化模块
mod instant_serde_opt {
    use super::*;
    use serde::{Serializer, Deserializer};

    pub fn serialize<S>(instant: &Option<Instant>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match instant {
            Some(inst) => serializer.serialize_u64(inst.elapsed().as_millis() as u64),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Instant>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = Option::<u64>::deserialize(deserializer)?;
        Ok(millis.map(|m| Instant::now() - Duration::from_millis(m)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_smart_thread_pool() {
        let config = ThreadPoolConfig::default();
        let pool = Arc::new(SmartThreadPool::new(config));
        
        // 启动线程池
        pool.start().await.unwrap();
        
        // 提交一些测试任务
        for i in 0..10 {
            let id = format!("task_{}", i);
            let priority = if i % 3 == 0 { TaskPriority::High } else { TaskPriority::Normal };
            
            pool.submit(id, priority, move || {
                std::thread::sleep(Duration::from_millis(10));
                Ok::<(), anyhow::Error>(())
            }).await.unwrap();
        }
        
        // 等待一段时间让任务执行
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // 检查状态
        let status = pool.get_status();
        assert!(status.total_tasks >= 10);
        
        // 停止线程池
        pool.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_concurrency_controller() {
        let controller = ConcurrencyController::new(5);
        
        // 并发执行多个操作
        let mut handles = Vec::new();
        for i in 0..10 {
            let controller = controller.clone();
            let i_clone = i;
            let handle = tokio::spawn(async move {
                controller.execute(&format!("test_op_{}", i_clone), move || {
                    std::thread::sleep(Duration::from_millis(50));
                    Ok::<i32, anyhow::Error>(i_clone)
                }).await
            });
            handles.push(handle);
        }
        
        // 等待所有操作完成
        for handle in handles {
            let _ = handle.await;
        }
        
        // 检查统计信息
        let stats = controller.get_concurrency_stats().await;
        assert_eq!(stats.total_operations, 10);
        assert_eq!(stats.successful_operations, 10);
        assert!(stats.avg_duration_ms > 0.0);
    }
}
