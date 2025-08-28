use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;

// 简单的测试，不依赖复杂的模块结构
#[tokio::test]
async fn test_basic_functionality() {
    // 测试基本的数据结构
    let mut map = HashMap::new();
    map.insert("test".to_string(), 42);
    
    assert_eq!(map.get("test"), Some(&42));
    assert_eq!(map.len(), 1);
}

#[tokio::test]
async fn test_arc_rwlock() {
    // 测试 Arc 和 RwLock 的基本功能
    let data = Arc::new(RwLock::new(42));
    
    // 读取
    let value = data.read().await;
    assert_eq!(*value, 42);
    drop(value);
    
    // 写入
    {
        let mut value = data.write().await;
        *value = 100;
    }
    
    // 再次读取
    let value = data.read().await;
    assert_eq!(*value, 100);
}

#[tokio::test]
async fn test_async_operations() {
    // 测试异步操作
    let result = tokio::time::timeout(
        tokio::time::Duration::from_millis(100),
        async {
            tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
            "success"
        }
    ).await;
    
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), "success");
}

#[tokio::test]
async fn test_error_handling() {
    // 测试错误处理
    let result: Result<String, &str> = Err("test error");
    
    match result {
        Ok(_) => panic!("Expected error"),
        Err(e) => assert_eq!(e, "test error"),
    }
}
