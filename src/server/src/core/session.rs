//! 会话管理与状态机
//!
//! 提供抽奖/投票会话的创建、状态转换、超时与审计。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Created,
    CommitmentOpen,
    CommitmentClosed,
    RevealOpen,
    RevealClosed,
    SelectionComputed,
    Finalized,
    Cancelled,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub state: SessionState,
    pub params: serde_json::Value,
    pub created_at: u64,
    pub updated_at: u64,
    pub deadlines: HashMap<String, u64>,
}

impl Session {
    #[allow(dead_code)]
    fn new(id: String, params: serde_json::Value) -> Self {
        let now = now_secs();
        Self { id, state: SessionState::Created, params, created_at: now, updated_at: now, deadlines: HashMap::new() }
    }
}

#[derive(Default)]
struct SessionStore { 
    #[allow(dead_code)]
    map: HashMap<String, Session>, 
    #[allow(dead_code)]
    audit: Vec<AuditEvent> 
}

#[derive(Clone, Default)]
pub struct SessionManager { 
    #[allow(dead_code)]
    inner: Arc<RwLock<SessionStore>> 
}

impl SessionManager {
    #[allow(dead_code)]
    pub fn new() -> Self { Self::default() }

    #[allow(dead_code)]
    pub async fn create(&self, id: String, params: serde_json::Value) -> Result<Session, String> {
        let mut g = self.inner.write().await;
        if g.map.contains_key(&id) { return Err("会话已存在".into()); }
        let sess = Session::new(id.clone(), params);
        g.audit.push(AuditEvent::created(&id));
        g.map.insert(id.clone(), sess.clone());
        Ok(sess)
    }

    #[allow(dead_code)]
    pub async fn set_deadline(&self, id: &str, key: &str, ts: u64) -> Result<(), String> {
        let mut g = self.inner.write().await;
        let s = g.map.get_mut(id).ok_or_else(|| "会话不存在".to_string())?;
        s.deadlines.insert(key.to_string(), ts);
        s.updated_at = now_secs();
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn get(&self, id: &str) -> Option<Session> {
        let g = self.inner.read().await;
        g.map.get(id).cloned()
    }

    #[allow(dead_code)]
    pub async fn transition(&self, id: &str, to: SessionState) -> Result<Session, String> {
        let (ret, ev) = {
            let mut g = self.inner.write().await;
            let sess = g.map.get_mut(id).ok_or_else(|| "会话不存在".to_string())?;
            validate_transition(&sess.state, &to)?;
            sess.state = to.clone();
            sess.updated_at = now_secs();
            let ret = sess.clone();
            let ev = AuditEvent::transitioned(id, &to);
            (ret, ev)
        };
        // push audit after releasing mutable borrow on map entry
        self.inner.write().await.audit.push(ev);
        Ok(ret)
    }

    #[allow(dead_code)]
    pub async fn cancel(&self, id: &str) -> Result<Session, String> {
        let (ret, ev) = {
            let mut g = self.inner.write().await;
            let sess = g.map.get_mut(id).ok_or_else(|| "会话不存在".to_string())?;
            sess.state = SessionState::Cancelled;
            sess.updated_at = now_secs();
            let ret = sess.clone();
            let ev = AuditEvent::cancelled(id);
            (ret, ev)
        };
        self.inner.write().await.audit.push(ev);
        Ok(ret)
    }

    #[allow(dead_code)]
    pub async fn audit_logs(&self) -> Vec<AuditEvent> {
        self.inner.read().await.audit.clone()
    }
}

#[allow(dead_code)]
fn validate_transition(from: &SessionState, to: &SessionState) -> Result<(), String> {
    use SessionState::*;
    let ok = matches!((from, to),
        (Created, CommitmentOpen)
        | (CommitmentOpen, CommitmentClosed)
        | (CommitmentClosed, RevealOpen)
        | (RevealOpen, RevealClosed)
        | (RevealClosed, SelectionComputed)
        | (SelectionComputed, Finalized)
    );
    if ok { Ok(()) } else { Err(format!("非法状态转换: {:?} -> {:?}", from, to)) }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent { pub ts: u64, pub action: AuditAction, pub session_id: String, pub state: Option<SessionState> }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction { Created, Transitioned, Cancelled }

impl AuditEvent {
    #[allow(dead_code)]
    fn created(id: &str) -> Self { Self { ts: now_secs(), action: AuditAction::Created, session_id: id.to_string(), state: Some(SessionState::Created) } }
    #[allow(dead_code)]
    fn transitioned(id: &str, to: &SessionState) -> Self { Self { ts: now_secs(), action: AuditAction::Transitioned, session_id: id.to_string(), state: Some(to.clone()) } }
    #[allow(dead_code)]
    fn cancelled(id: &str) -> Self { Self { ts: now_secs(), action: AuditAction::Cancelled, session_id: id.to_string(), state: Some(SessionState::Cancelled) } }
}

#[allow(dead_code)]
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_session_lifecycle() {
        let mgr = SessionManager::new();
        let s = mgr.create("s1".into(), serde_json::json!({"k": 10})).await.unwrap();
        assert_eq!(s.state, SessionState::Created);
        mgr.transition("s1", SessionState::CommitmentOpen).await.unwrap();
        mgr.transition("s1", SessionState::CommitmentClosed).await.unwrap();
        mgr.transition("s1", SessionState::RevealOpen).await.unwrap();
        mgr.transition("s1", SessionState::RevealClosed).await.unwrap();
        mgr.transition("s1", SessionState::SelectionComputed).await.unwrap();
        let s2 = mgr.transition("s1", SessionState::Finalized).await.unwrap();
        assert_eq!(s2.state, SessionState::Finalized);
        let logs = mgr.audit_logs().await;
        assert!(logs.iter().any(|e| matches!(e.action, AuditAction::Created)));
        assert!(logs.iter().any(|e| matches!(e.action, AuditAction::Transitioned)));
    }

    #[tokio::test]
    async fn test_invalid_transition() {
        let mgr = SessionManager::new();
        mgr.create("s2".into(), serde_json::json!({})).await.unwrap();
        let err = mgr.transition("s2", SessionState::RevealOpen).await.err().unwrap();
        assert!(err.contains("非法状态转换"));
    }
}


