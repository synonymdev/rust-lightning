//! Storage fault injection for the actual background-processor completion hooks.

use super::*;
use core::future::Future;
use core::pin::Pin;
use lightning::sign::ChangeDestinationSourceSyncWrapper;
use lightning::util::async_poll::AsyncResult;
use std::sync::{mpsc, Mutex};
use tokio::sync::{mpsc as async_mpsc, oneshot, watch};

type WriteResult = Result<(), std::io::ErrorKind>;

pub(super) struct SyncWriteGate {
	started: mpsc::SyncSender<()>,
	complete: Mutex<mpsc::Receiver<WriteResult>>,
}

impl SyncWriteGate {
	pub(super) fn wait(&self) -> lightning::io::Result<()> {
		self.started.send(()).unwrap();
		self.complete
			.lock()
			.unwrap()
			.recv_timeout(EVENT_DEADLINE)
			.unwrap()
			.map_err(|kind| std::io::Error::new(kind, "injected write failure").into())
	}
}

#[test]
fn ffor_sync_completion_waits_for_storage_and_preserves_later_revision_on_error() {
	let (_, nodes) = create_nodes(1, "ffor_sync_persistence");
	let node = &nodes[0];
	let first = node.node.testing_request_ffor_persistence();
	let (started, writes) = mpsc::sync_channel(1);
	let (complete, results) = mpsc::sync_channel(1);
	let mut store = Persister::new(node.kv_store.get_data_dir());
	store.manager_write_gate = Some(SyncWriteGate { started, complete: Mutex::new(results) });
	let processor = BackgroundProcessor::start(
		Arc::new(store),
		|_| Ok(()),
		Arc::clone(&node.chain_monitor),
		Arc::clone(&node.node),
		Some(Arc::clone(&node.messenger)),
		node.no_gossip_sync(),
		Arc::clone(&node.peer_manager),
		Some(Arc::clone(&node.liquidity_manager)),
		Some(Arc::clone(&node.sweeper)),
		Arc::clone(&node.logger),
		Some(Arc::clone(&node.scorer)),
	);
	writes.recv_timeout(EVENT_DEADLINE).unwrap();
	assert!(!node.node.is_ffor_state_persisted(&first));
	assert!(read_manager(node).is_err());
	let later = node.node.testing_request_ffor_persistence();
	complete.send(Ok(())).unwrap();
	writes.recv_timeout(EVENT_DEADLINE).unwrap();
	assert!(node.node.is_ffor_state_persisted(&first));
	assert!(read_manager(node).is_ok());
	assert!(!node.node.is_ffor_state_persisted(&later));
	complete.send(Err(std::io::ErrorKind::Other)).unwrap();
	assert_eq!(processor.join().unwrap_err().kind(), std::io::ErrorKind::Other);
	assert!(!node.node.is_ffor_state_persisted(&later));
	assert!(node.node.get_and_clear_needs_persistence());
}

fn read_manager(node: &Node) -> lightning::io::Result<Vec<u8>> {
	node.kv_store.read(
		CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE,
		CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE,
		CHANNEL_MANAGER_PERSISTENCE_KEY,
	)
}

struct AsyncStore {
	inner: Arc<Persister>,
	writes: async_mpsc::UnboundedSender<oneshot::Sender<WriteResult>>,
}

impl lightning::util::persist::KVStore for AsyncStore {
	fn read(
		&self, primary: &str, secondary: &str, key: &str,
	) -> AsyncResult<'static, Vec<u8>, lightning::io::Error> {
		let result = self.inner.read(primary, secondary, key);
		Box::pin(async move { result })
	}

	fn write(
		&self, primary: &str, secondary: &str, key: &str, buf: Vec<u8>,
	) -> AsyncResult<'static, (), lightning::io::Error> {
		let inner = Arc::clone(&self.inner);
		let names = (primary.to_owned(), secondary.to_owned(), key.to_owned());
		let gate = if primary == CHANNEL_MANAGER_PERSISTENCE_PRIMARY_NAMESPACE
			&& secondary == CHANNEL_MANAGER_PERSISTENCE_SECONDARY_NAMESPACE
			&& key == CHANNEL_MANAGER_PERSISTENCE_KEY
		{
			let (complete, gate) = oneshot::channel();
			self.writes.send(complete).unwrap();
			Some(gate)
		} else {
			None
		};
		Box::pin(async move {
			if let Some(gate) = gate {
				gate.await
					.unwrap()
					.map_err(|kind| std::io::Error::new(kind, "injected write failure"))?;
			}
			inner.write(&names.0, &names.1, &names.2, buf)
		})
	}

	fn remove(
		&self, primary: &str, secondary: &str, key: &str, lazy: bool,
	) -> AsyncResult<'static, (), lightning::io::Error> {
		let result = self.inner.remove(primary, secondary, key, lazy);
		Box::pin(async move { result })
	}

	fn list(
		&self, primary: &str, secondary: &str,
	) -> AsyncResult<'static, Vec<String>, lightning::io::Error> {
		let result = self.inner.list(primary, secondary);
		Box::pin(async move { result })
	}
}

type AsyncSweeper = OutputSweeper<
	Arc<test_utils::TestBroadcaster>,
	ChangeDestinationSourceSyncWrapper<Arc<TestWallet>>,
	Arc<test_utils::TestFeeEstimator>,
	Arc<test_utils::TestChainSource>,
	Arc<AsyncStore>,
	Arc<test_utils::TestLogger>,
	Arc<KeysManager>,
>;

async fn run_async(
	node: &Node, store: Arc<AsyncStore>, stop: watch::Receiver<bool>,
) -> lightning::io::Result<()> {
	super::super::process_events_async(
		store,
		|_| async { Ok(()) },
		Arc::clone(&node.chain_monitor),
		Arc::clone(&node.node),
		Some(Arc::clone(&node.messenger)),
		node.no_gossip_sync(),
		Arc::clone(&node.peer_manager),
		Some(node.liquidity_manager.get_lm_async()),
		None::<Arc<AsyncSweeper>>,
		Arc::clone(&node.logger),
		Some(Arc::clone(&node.scorer)),
		move |duration| {
			let mut stop = stop.clone();
			Box::pin(async move {
				if *stop.borrow() {
					return true;
				}
				tokio::select! {
					_ = tokio::time::sleep(duration) => false,
					_ = stop.changed() => true,
				}
			})
		},
		false,
		|| Some(Duration::ZERO),
	)
	.await
}

async fn next_write<F: Future<Output = lightning::io::Result<()>>>(
	processor: Pin<&mut F>,
	writes: &mut async_mpsc::UnboundedReceiver<oneshot::Sender<WriteResult>>,
) -> oneshot::Sender<WriteResult> {
	tokio::select! {
		result = processor => panic!("processor exited before expected write: {:?}", result),
		write = tokio::time::timeout(EVENT_DEADLINE, writes.recv()) => write.unwrap().unwrap(),
	}
}

#[tokio::test]
async fn ffor_async_completion_waits_for_storage_and_preserves_later_revision_on_error() {
	let (_, nodes) = create_nodes(1, "ffor_async_persistence");
	let node = &nodes[0];
	let first = node.node.testing_request_ffor_persistence();
	let (writes_tx, mut writes) = async_mpsc::unbounded_channel();
	let store = Arc::new(AsyncStore { inner: Arc::clone(&node.kv_store), writes: writes_tx });
	let (_stop_tx, stop) = watch::channel(false);
	let mut processor = Box::pin(run_async(node, store, stop));
	let complete = next_write(processor.as_mut(), &mut writes).await;
	assert!(!node.node.is_ffor_state_persisted(&first));
	assert!(read_manager(node).is_err());
	let later = node.node.testing_request_ffor_persistence();
	complete.send(Ok(())).unwrap();
	let complete = next_write(processor.as_mut(), &mut writes).await;
	assert!(node.node.is_ffor_state_persisted(&first));
	assert!(read_manager(node).is_ok());
	assert!(!node.node.is_ffor_state_persisted(&later));
	complete.send(Err(std::io::ErrorKind::Other)).unwrap();
	let error = tokio::time::timeout(EVENT_DEADLINE, processor).await.unwrap().unwrap_err();
	assert_eq!(error.kind(), lightning::io::ErrorKind::Other);
	assert!(!node.node.is_ffor_state_persisted(&later));
	assert!(node.node.get_and_clear_needs_persistence());
}

#[tokio::test]
async fn ffor_cancelled_async_write_requires_retry_and_final_shutdown_write() {
	let (_, nodes) = create_nodes(1, "ffor_cancelled_persistence");
	let node = &nodes[0];
	let requirement = node.node.testing_request_ffor_persistence();
	let (writes_tx, mut writes) = async_mpsc::unbounded_channel();
	let store = Arc::new(AsyncStore { inner: Arc::clone(&node.kv_store), writes: writes_tx });
	let (stop_tx, stop) = watch::channel(false);
	let mut processor = Box::pin(run_async(node, Arc::clone(&store), stop.clone()));
	let cancelled = next_write(processor.as_mut(), &mut writes).await;
	drop(processor);
	assert!(cancelled.send(Ok(())).is_err());
	assert!(read_manager(node).is_err());
	assert!(!node.node.is_ffor_state_persisted(&requirement));
	assert!(node.node.get_and_clear_needs_persistence());

	let mut processor = Box::pin(run_async(node, store, stop));
	let retry = next_write(processor.as_mut(), &mut writes).await;
	let later = node.node.testing_request_ffor_persistence();
	stop_tx.send(true).unwrap();
	retry.send(Ok(())).unwrap();
	let final_write = next_write(processor.as_mut(), &mut writes).await;
	assert!(node.node.is_ffor_state_persisted(&requirement));
	assert!(!node.node.is_ffor_state_persisted(&later));
	assert!(read_manager(node).is_ok());
	final_write.send(Ok(())).unwrap();
	tokio::time::timeout(EVENT_DEADLINE, processor).await.unwrap().unwrap();
	assert!(node.node.is_ffor_state_persisted(&later));
	assert!(read_manager(node).is_ok());
}

#[test]
fn ffor_sync_shutdown_completes_only_its_final_durable_snapshot() {
	let (_, nodes) = create_nodes(1, "ffor_sync_shutdown_persistence");
	let node = &nodes[0];
	let first = node.node.testing_request_ffor_persistence();
	let (started, writes) = mpsc::sync_channel(1);
	let (complete, results) = mpsc::sync_channel(1);
	let mut store = Persister::new(node.kv_store.get_data_dir());
	store.manager_write_gate = Some(SyncWriteGate { started, complete: Mutex::new(results) });
	let processor = BackgroundProcessor::start(
		Arc::new(store),
		|_| Ok(()),
		Arc::clone(&node.chain_monitor),
		Arc::clone(&node.node),
		Some(Arc::clone(&node.messenger)),
		node.no_gossip_sync(),
		Arc::clone(&node.peer_manager),
		Some(Arc::clone(&node.liquidity_manager)),
		Some(Arc::clone(&node.sweeper)),
		Arc::clone(&node.logger),
		Some(Arc::clone(&node.scorer)),
	);
	writes.recv_timeout(EVENT_DEADLINE).unwrap();
	let later = node.node.testing_request_ffor_persistence();
	processor.stop_thread.store(true, std::sync::atomic::Ordering::Release);
	complete.send(Ok(())).unwrap();
	writes.recv_timeout(EVENT_DEADLINE).unwrap();
	assert!(node.node.is_ffor_state_persisted(&first));
	assert!(!node.node.is_ffor_state_persisted(&later));
	complete.send(Ok(())).unwrap();
	processor.join().unwrap();
	assert!(node.node.is_ffor_state_persisted(&later));
	assert!(read_manager(node).is_ok());
}
