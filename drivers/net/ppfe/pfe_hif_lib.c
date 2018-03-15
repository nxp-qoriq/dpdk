/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2018 NXP
 */

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/sched.h>

#include <rte_net.h>

#include "pfe_logs.h"
#include "pfe_mod.h"
#include "pfe_hif.h"
#include "pfe_hif_lib.h"

unsigned int page_mode;
unsigned int tx_qos = 1;
unsigned int pfe_pkt_size;
unsigned int pfe_pkt_headroom;
unsigned int emac_txq_cnt;

/*
 * @pfe_hal_lib.c
 * Common functions used by HIF client drivers
 */

/*HIF shared memory Global variable */
struct hif_shm ghif_shm;

/* Cleanup the HIF shared memory, release HIF rx_buffer_pool.
 * This function should be called after pfe_hif_exit
 *
 * @param[in] hif_shm		Shared memory address location in DDR
 */
void pfe_hif_shm_clean(struct hif_shm *hif_shm)
{
	unsigned int i;
//	struct rte_mbuf *mbuf, *dummy_mbuf;
	void *pkt;

//	dummy_mbuf = rte_cpu_to_le_64(rte_pktmbuf_alloc(hif_shm->pool));
	for (i = 0; i < hif_shm->rx_buf_pool_cnt; i++) {
		pkt = hif_shm->rx_buf_pool[i];
		if (pkt) {
#if 0
			hif_shm->rx_buf_pool[i] = NULL;
			pkt += PFE_PKT_HEADER_SZ;

			mbuf = (struct rte_mbuf *) pkt - dummy_mbuf->data_off;
#endif
			rte_pktmbuf_free((struct rte_mbuf *)pkt);
		}
	}
//	rte_pktmbuf_free(dummy_mbuf);
}

/* Initialize shared memory used between HIF driver and clients,
 * allocate rx_buffer_pool required for HIF Rx descriptors.
 * This function should be called before initializing HIF driver.
 *
 * @param[in] hif_shm		Shared memory address location in DDR
 * @rerurn			0 - on succes, <0 on fail to initialize
 */
int pfe_hif_shm_init(struct hif_shm *hif_shm, struct rte_mempool *mb_pool)
{
	unsigned int i;
//	void *pkt;
	struct rte_mbuf *mbuf;

	memset(hif_shm, 0, sizeof(struct hif_shm));
	hif_shm->rx_buf_pool_cnt = HIF_RX_DESC_NT;

	for (i = 0; i < hif_shm->rx_buf_pool_cnt; i++) {
		mbuf = rte_cpu_to_le_64(rte_pktmbuf_alloc(mb_pool));
//		pkt = (void *)((size_t)mbuf->buf_addr + mbuf->data_off);
		if (mbuf)
			hif_shm->rx_buf_pool[i] = mbuf;
//			hif_shm->rx_buf_pool[i] = pkt - PFE_PKT_HEADER_SZ;
		else
			goto err0;
	}

	return 0;

err0:
	PFE_PMD_ERR("Low memory");
	pfe_hif_shm_clean(hif_shm);
	return -ENOMEM;
}

/*This function sends indication to HIF driver
 *
 * @param[in] hif	hif context
 */
static void hif_lib_indicate_hif(struct pfe_hif *hif, int req, int data1, int
					data2)
{
	hif_process_client_req(hif, req, data1, data2);
}

void hif_lib_indicate_client(struct hif_client_s *client, int event_type, int qno)
{
	if (!client || (event_type >= HIF_EVENT_MAX) || (qno >=
		HIF_CLIENT_QUEUES_MAX))
		return;

	if (!test_and_set_bit(qno, &client->queue_mask[event_type])) {
		client->event_handler(client->priv, event_type, qno);
	}
}

/*This function releases Rx queue descriptors memory and pre-filled buffers
 *
 * @param[in] client	hif_client context
 */
static void hif_lib_client_release_rx_buffers(struct hif_client_s *client)
{
	struct rx_queue_desc *desc;
	unsigned int qno, ii;
	void *buf;

	for (qno = 0; qno < client->rx_qn; qno++) {
		desc = client->rx_q[qno].base;

		for (ii = 0; ii < client->rx_q[qno].size; ii++) {
			buf = (void *)desc->data;
			if (buf) {
				buf -= pfe_pkt_headroom;
				rte_pktmbuf_free(buf);
				desc->ctrl = 0;
			}

			desc++;
		}
	}

	rte_free(client->rx_qbase);
}

/*This function allocates memory for the rxq descriptors and pre-fill rx queues
 * with buffers.
 * @param[in] client	client context
 * @param[in] q_size	size of the rxQ, all queues are of same size
 */
static int hif_lib_client_init_rx_buffers(struct hif_client_s *client,
					  int q_size)
{
	struct rx_queue_desc *desc;
	struct hif_client_rx_queue *queue;
	unsigned int ii, qno;

	/*Allocate memory for the client queues */
	client->rx_qbase = rte_malloc(NULL, client->rx_qn * q_size * sizeof(struct
				rx_queue_desc), RTE_CACHE_LINE_SIZE);
	if (!client->rx_qbase)
		goto err;

	for (qno = 0; qno < client->rx_qn; qno++) {
		queue = &client->rx_q[qno];

		queue->base = client->rx_qbase + qno * q_size * sizeof(struct
				rx_queue_desc);
		queue->size = q_size;
		queue->read_idx = 0;
		queue->write_idx = 0;
		queue->queue_id = 0;
		queue->port_id = client->port_id;
		queue->priv = client->priv;
		pr_debug("rx queue: %d, base: %p, size: %d\n", qno,
			 queue->base, queue->size);
	}

	for (qno = 0; qno < client->rx_qn; qno++) {
		queue = &client->rx_q[qno];
		desc = queue->base;

		for (ii = 0; ii < queue->size; ii++) {
			desc->ctrl = CL_DESC_BUF_LEN(pfe_pkt_size) |
					CL_DESC_OWN;
			desc++;
		}
	}

	return 0;

err:
	return 1;
}


static void hif_lib_client_cleanup_tx_queue(struct hif_client_tx_queue *queue)
{
	pr_debug("%s\n", __func__);

	/*
	 * Check if there are any pending packets. Client must flush the tx
	 * queues before unregistering, by calling by calling
	 * hif_lib_tx_get_next_complete()
	 *
	 * Hif no longer calls since we are no longer registered
	 */
	if (queue->tx_pending)
		PFE_PMD_ERR("pending transmit packet");
}

static void hif_lib_client_release_tx_buffers(struct hif_client_s *client)
{
	unsigned int qno;

	pr_debug("%s\n", __func__);

	for (qno = 0; qno < client->tx_qn; qno++)
		hif_lib_client_cleanup_tx_queue(&client->tx_q[qno]);

	rte_free(client->tx_qbase);
}

static int hif_lib_client_init_tx_buffers(struct hif_client_s *client, int
						q_size)
{
	struct hif_client_tx_queue *queue;
	unsigned int qno;

	client->tx_qbase = rte_malloc(NULL, client->tx_qn * q_size * sizeof(struct
					tx_queue_desc), RTE_CACHE_LINE_SIZE);
	if (!client->tx_qbase)
		return 1;

	for (qno = 0; qno < client->tx_qn; qno++) {
		queue = &client->tx_q[qno];

		queue->base = client->tx_qbase + qno * q_size * sizeof(struct
				tx_queue_desc);
		queue->size = q_size;
		queue->read_idx = 0;
		queue->write_idx = 0;
		queue->tx_pending = 0;
		queue->nocpy_flag = 0;
		queue->prev_tmu_tx_pkts = 0;
		queue->done_tmu_tx_pkts = 0;
		queue->priv = client->priv;
		queue->queue_id = 0;
		queue->port_id = client->port_id;

		PFE_PMD_DEBUG("tx queue: %d, base: %p, size: %d", qno,
			 queue->base, queue->size);
	}

	return 0;
}

static int hif_lib_event_dummy(__rte_unused void *priv,
		__rte_unused int event_type, __rte_unused int qno)
{
	return 0;
}

int hif_lib_client_register(struct hif_client_s *client)
{
	struct hif_shm *hif_shm;
	struct hif_client_shm *client_shm;
	int err, i;
	/* int loop_cnt = 0; */

	PMD_INIT_FUNC_TRACE();

	/*Allocate memory before spin_lock*/
	if (hif_lib_client_init_rx_buffers(client, client->rx_qsize)) {
		err = -ENOMEM;
		goto err_rx;
	}

	if (hif_lib_client_init_tx_buffers(client, client->tx_qsize)) {
		err = -ENOMEM;
		goto err_tx;
	}

	rte_spinlock_lock(&client->pfe->hif.lock);
	if (!(client->pfe) || (client->id >= HIF_CLIENTS_MAX)/* ||
	    (pfe->hif_client[client->id])*/) {
		err = -EINVAL;
		goto err;
	}

	hif_shm = client->pfe->hif.shm;

	if (!client->event_handler)
		client->event_handler = hif_lib_event_dummy;

	/*Initialize client specific shared memory */
	client_shm = (struct hif_client_shm *)&hif_shm->client[client->id];
	client_shm->rx_qbase = (unsigned long int)client->rx_qbase;
	client_shm->rx_qsize = client->rx_qsize;
	client_shm->tx_qbase = (unsigned long int)client->tx_qbase;
	client_shm->tx_qsize = client->tx_qsize;
	client_shm->ctrl = (client->tx_qn << CLIENT_CTRL_TX_Q_CNT_OFST) |
				(client->rx_qn << CLIENT_CTRL_RX_Q_CNT_OFST);

	for (i = 0; i < HIF_EVENT_MAX; i++) {
		client->queue_mask[i] = 0;  /*
					     * By default all events are
					     * unmasked
					     */
	}

	/*Indicate to HIF driver*/
	hif_lib_indicate_hif(&client->pfe->hif, REQUEST_CL_REGISTER, client->id, 0);

	PFE_PMD_DEBUG("client: %p, client_id: %d, tx_qsize: %d, rx_qsize: %d",
		      client, client->id, client->tx_qsize, client->rx_qsize);

	client->cpu_id = -1;

	client->pfe->hif_client[client->id] = client;
	rte_spinlock_unlock(&client->pfe->hif.lock);

	return 0;

err:
	rte_spinlock_unlock(&client->pfe->hif.lock);
	hif_lib_client_release_tx_buffers(client);

err_tx:
	hif_lib_client_release_rx_buffers(client);

err_rx:
	return err;
}

int hif_lib_client_unregister(struct hif_client_s *client)
{
	struct pfe *pfe = client->pfe;
	u32 client_id = client->id;

	PFE_PMD_INFO("client: %p, client_id: %d, txQ_depth: %d, rxQ_depth: %d",
		     client, client->id, client->tx_qsize, client->rx_qsize);

	rte_spinlock_lock(&pfe->hif.lock);
	hif_lib_indicate_hif(&pfe->hif, REQUEST_CL_UNREGISTER, client->id, 0);

	hif_lib_client_release_tx_buffers(client);
	hif_lib_client_release_rx_buffers(client);
	pfe->hif_client[client_id] = NULL;
	rte_spinlock_unlock(&pfe->hif.lock);

	return 0;
}

int hif_lib_event_handler_start(struct hif_client_s *client, int event,
				int qno)
{
	struct hif_client_rx_queue *queue = &client->rx_q[qno];
	struct rx_queue_desc *desc = queue->base + queue->read_idx;

	if ((event >= HIF_EVENT_MAX) || (qno >= HIF_CLIENT_QUEUES_MAX)) {
		PFE_PMD_WARN("Unsupported event : %d  queue number : %d",
				event, qno);
		return -1;
	}

	test_and_clear_bit(qno, &client->queue_mask[event]);

	switch (event) {
	case EVENT_RX_PKT_IND:
		if (!(desc->ctrl & CL_DESC_OWN))
			hif_lib_indicate_client(client,
						EVENT_RX_PKT_IND, qno);
		break;

	case EVENT_HIGH_RX_WM:
	case EVENT_TXDONE_IND:
	default:
		break;
	}

	return 0;
}

static inline void
pfe_sw_parse_pkt(struct rte_mbuf *mbuf)
{
	struct rte_net_hdr_lens hdr_lens;

	mbuf->packet_type = rte_net_get_ptype(mbuf, &hdr_lens,
			RTE_PTYPE_L2_MASK | RTE_PTYPE_L3_MASK
			| RTE_PTYPE_L4_MASK);
	mbuf->l2_len = hdr_lens.l2_len;
	mbuf->l3_len = hdr_lens.l3_len;
}

/*
 * This function gets one packet from the specified client queue
 * It also refill the rx buffer
 */
int hif_lib_receive_pkt_dpdk(struct hif_client_rx_queue *queue,
		struct rte_mempool *pool, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts)
{
	struct rx_queue_desc *desc;
//	unsigned int *rx_ctrl;
	struct rte_pktmbuf_pool_private *mb_priv;
	struct rte_mbuf *mbuf;
	int i;

	for (i = 0; i < nb_pkts; i++) {

		desc = queue->base + queue->read_idx;
		if ((desc->ctrl & CL_DESC_OWN))
			return i;

		mb_priv = rte_mempool_get_priv(pool);
		/*TODO optimize the code and remove local buf storage pointors*/
		mbuf = desc->data + PFE_PKT_HEADER_SZ
			- sizeof(struct rte_mbuf)
			- RTE_PKTMBUF_HEADROOM
			- mb_priv->mbuf_priv_size;

		/*TODO whats is the use of these*/
//		*rx_ctrl = desc->client_ctrl;
//		*desc_ctrl = desc->ctrl;
		if (desc->ctrl & CL_DESC_FIRST) {
			/*TODO when we get size and private data */
			//u16 size = *rx_ctrl >> HIF_CTRL_RX_OFFSET_OFST;
			u16 size = 0;

			mbuf->pkt_len = CL_DESC_BUF_LEN(desc->ctrl)
					- PFE_PKT_HEADER_SZ - size;
			//*ofst = pfe_pkt_headroom + PFE_PKT_HEADER_SZ + size;

			if (size) {
				PFE_PMD_WARN(
				"size = %d is there so wrong data point to",
				size);
				//*priv_data = desc->data + PFE_PKT_HEADER_SZ;
			} else {
				//*priv_data = NULL;
			}

		} else {
			mbuf->pkt_len = CL_DESC_BUF_LEN(desc->ctrl);
			//*ofst = pfe_pkt_headroom;
		}
		mbuf->data_len = mbuf->pkt_len;
		mbuf->port = queue->port_id;
		pfe_sw_parse_pkt(mbuf);
		mbuf->nb_segs = 1;
		mbuf->next = NULL;

		rx_pkts[i] = mbuf;

		/*
		 * Needed so we don't free a buffer/page
		 * twice on module_exit
		 */
		desc->data = NULL;

		/*
		 * Ensure everything else is written to DDR before
		 * writing bd->ctrl
		 */
		rte_wmb();

		desc->ctrl = CL_DESC_BUF_LEN(pfe_pkt_size) | CL_DESC_OWN;
		queue->read_idx = (queue->read_idx + 1) & (queue->size - 1);
	}
	return i;
}

static inline void hif_hdr_write(struct hif_hdr *pkt_hdr, unsigned int
					client_id, unsigned int qno,
					u32 client_ctrl)
{
	/* Optimize the write since the destinaton may be non-cacheable */
	if (!((unsigned long)pkt_hdr & 0x3)) {
		((u32 *)pkt_hdr)[0] = (client_ctrl << 16) | (qno << 8) |
					client_id;
	} else {
		((u16 *)pkt_hdr)[0] = (qno << 8) | (client_id & 0xFF);
		((u16 *)pkt_hdr)[1] = (client_ctrl & 0xFFFF);
	}
}

/*This function puts the given packet in the specific client queue */
void __hif_lib_xmit_pkt(struct hif_client_s *client, unsigned int qno,
			void *data, void *data1, unsigned int len,
			u32 client_ctrl, unsigned int flags, void *client_data)
{
	struct hif_client_tx_queue *queue = &client->tx_q[qno];
	struct tx_queue_desc *desc = queue->base + queue->write_idx;

	/* First buffer */
	if (flags & HIF_FIRST_BUFFER) {
		data1 -= sizeof(struct hif_hdr);
		data -= sizeof(struct hif_hdr);
		len += sizeof(struct hif_hdr);

		hif_hdr_write(data1, client->id, qno, client_ctrl);
	}

	desc->data = client_data;
	desc->ctrl = CL_DESC_OWN | CL_DESC_FLAGS(flags);

	__hif_xmit_pkt(&client->pfe->hif, client->id, qno, data, len, flags);

	queue->write_idx = (queue->write_idx + 1) & (queue->size - 1);

	queue->tx_pending++;
}

void *hif_lib_tx_get_next_complete(struct hif_client_s *client, int qno,
				   unsigned int *flags,__rte_unused  int count)
{
	struct hif_client_tx_queue *queue = &client->tx_q[qno];
	struct tx_queue_desc *desc = queue->base + queue->read_idx;

	PFE_DP_LOG(DEBUG, "qno : %d rd_indx: %d pending:%d",
		   qno, queue->read_idx, queue->tx_pending);

	if (!queue->tx_pending)
		return NULL;

	if (queue->nocpy_flag && !queue->done_tmu_tx_pkts) {
		u32 tmu_tx_pkts = 0; //rte_be_to_cpu_32(pe_dmem_read(TMU0_ID +
			// client->id, TMU_DM_TX_TRANS, 4));

		if (queue->prev_tmu_tx_pkts > tmu_tx_pkts)
			queue->done_tmu_tx_pkts = UINT_MAX -
				queue->prev_tmu_tx_pkts + tmu_tx_pkts;
		else
			queue->done_tmu_tx_pkts = tmu_tx_pkts -
						queue->prev_tmu_tx_pkts;

		queue->prev_tmu_tx_pkts  = tmu_tx_pkts;

		if (!queue->done_tmu_tx_pkts)
			return NULL;
	}

	if (desc->ctrl & CL_DESC_OWN)
		return NULL;

	queue->read_idx = (queue->read_idx + 1) & (queue->size - 1);
	queue->tx_pending--;

	*flags = CL_DESC_GET_FLAGS(desc->ctrl);

	if (queue->done_tmu_tx_pkts && (*flags & HIF_LAST_BUFFER))
		queue->done_tmu_tx_pkts--;

	return desc->data;
}

/*TODO what are credits?*/
static void hif_lib_tmu_credit_init(__rte_unused struct pfe *pfe)
{
}

/* __hif_lib_update_credit
 *
 * @param[in] client	hif client context
 * @param[in] queue	queue number in match with TMU
 */
void __hif_lib_update_credit(__rte_unused struct hif_client_s *client,
		__rte_unused unsigned int queue)
{
}

int pfe_hif_lib_init(struct pfe *pfe)
{
	PMD_INIT_FUNC_TRACE();

	page_mode = 0;
	pfe_pkt_size = 1024;//PFE_PKT_SIZE;
	pfe_pkt_headroom = PFE_PKT_HEADROOM;

	if (tx_qos)
		emac_txq_cnt = EMAC_TXQ_CNT / 2;
	else
		emac_txq_cnt = EMAC_TXQ_CNT;

	hif_lib_tmu_credit_init(pfe);
	pfe->hif.shm = &ghif_shm;

	return 0;
}

void pfe_hif_lib_exit(__rte_unused struct pfe *pfe)
{
	PMD_INIT_FUNC_TRACE();

}
