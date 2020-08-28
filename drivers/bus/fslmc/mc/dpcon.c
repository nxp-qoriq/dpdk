/* SPDX-License-Identifier: (BSD-3-Clause OR GPL-2.0)
 *
 * Copyright 2013-2016 Freescale Semiconductor Inc.
 * Copyright 2017-2020 NXP
 *
 */
#include <fsl_mc_sys.h>
#include <fsl_mc_cmd.h>
#include <fsl_dpcon.h>
#include <fsl_dpcon_cmd.h>

/**
 * dpcon_open() - Open a control session for the specified object
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @dpcon_id:	DPCON unique ID
 * @token:	Returned token; use in subsequent API calls
 *
 * This function can be used to open a control session for an
 * already created object; an object may have been declared in
 * the DPL or by calling the dpcon_create() function.
 * This function returns a unique authentication token,
 * associated with the specific object ID and the specific MC
 * portal; this token must be used in all subsequent commands for
 * this specific object.
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpcon_open(struct fsl_mc_io *mc_io,
	       uint32_t cmd_flags,
	       int dpcon_id,
	       uint16_t *token)
{
	struct mc_command cmd = { 0 };
	struct dpcon_cmd_open *dpcon_cmd;
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPCON_CMDID_OPEN,
					  cmd_flags,
					  0);
	dpcon_cmd = (struct dpcon_cmd_open *)cmd.params;
	dpcon_cmd->dpcon_id = cpu_to_le32(dpcon_id);

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	*token = mc_cmd_hdr_read_token(&cmd);

	return 0;
}

/**
 * dpcon_close() - Close the control session of the object
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPCON object
 *
 * After this function is called, no further operations are
 * allowed on the object without opening a new control session.
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpcon_close(struct fsl_mc_io *mc_io,
		uint32_t cmd_flags,
		uint16_t token)
{
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPCON_CMDID_CLOSE,
					  cmd_flags,
					  token);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpcon_create() - Create the DPCON object.
 * @mc_io:	Pointer to MC portal's I/O object
 * @dprc_token:	Parent container token; '0' for default container
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @cfg:	Configuration structure
 * @obj_id:	Returned object id; use in subsequent API calls
 *
 * Create the DPCON object, allocate required resources and
 * perform required initialization.
 *
 * The object can be created either by declaring it in the
 * DPL file, or by calling this function.
 *
 * This function accepts an authentication token of a parent
 * container that this object should be assigned to and returns
 * an object id. This object_id will be used in all subsequent calls to
 * this specific object.
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpcon_create(struct fsl_mc_io *mc_io,
		 uint16_t dprc_token,
		 uint32_t cmd_flags,
		 const struct dpcon_cfg *cfg,
		 uint32_t *obj_id)
{
	struct dpcon_cmd_create *dpcon_cmd;
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPCON_CMDID_CREATE,
					  cmd_flags,
					  dprc_token);
	dpcon_cmd = (struct dpcon_cmd_create *)cmd.params;
	dpcon_cmd->num_priorities = cfg->num_priorities;

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	*obj_id = mc_cmd_read_object_id(&cmd);

	return 0;
}

/**
 * dpcon_destroy() - Destroy the DPCON object and release all its resources.
 * @mc_io:	Pointer to MC portal's I/O object
 * @dprc_token:	Parent container token; '0' for default container
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @obj_id:	ID of DPCON object
 *
 * Return:	'0' on Success; error code otherwise.
 */
int dpcon_destroy(struct fsl_mc_io *mc_io,
		  uint16_t dprc_token,
		  uint32_t cmd_flags,
		  uint32_t obj_id)
{
	struct dpcon_cmd_destroy *cmd_params;
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPCON_CMDID_DESTROY,
					  cmd_flags,
					  dprc_token);
	cmd_params = (struct dpcon_cmd_destroy *)cmd.params;
	cmd_params->object_id = cpu_to_le32(obj_id);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpcon_enable() - Enable the DPCON
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPCON object
 *
 * Return:	'0' on Success; Error code otherwise
 */
int dpcon_enable(struct fsl_mc_io *mc_io,
		 uint32_t cmd_flags,
		 uint16_t token)
{
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPCON_CMDID_ENABLE,
					  cmd_flags,
					  token);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpcon_disable() - Disable the DPCON
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPCON object
 *
 * Return:	'0' on Success; Error code otherwise
 */
int dpcon_disable(struct fsl_mc_io *mc_io,
		  uint32_t cmd_flags,
		  uint16_t token)
{
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPCON_CMDID_DISABLE,
					  cmd_flags,
					  token);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpcon_is_enabled() -	Check if the DPCON is enabled.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPCON object
 * @en:		Returns '1' if object is enabled; '0' otherwise
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpcon_is_enabled(struct fsl_mc_io *mc_io,
		     uint32_t cmd_flags,
		     uint16_t token,
		     int *en)
{
	struct dpcon_rsp_is_enabled *dpcon_rsp;
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPCON_CMDID_IS_ENABLED,
					  cmd_flags,
					  token);

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	dpcon_rsp = (struct dpcon_rsp_is_enabled *)cmd.params;
	*en = dpcon_rsp->enabled & DPCON_ENABLE;

	return 0;
}

/**
 * dpcon_reset() - Reset the DPCON, returns the object to initial state.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPCON object
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpcon_reset(struct fsl_mc_io *mc_io,
		uint32_t cmd_flags,
		uint16_t token)
{
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPCON_CMDID_RESET,
					  cmd_flags, token);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpcon_set_irq_enable() - Set overall interrupt state.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPCON object
 * @irq_index:	The interrupt index to configure
 * @en:		Interrupt state - enable = 1, disable = 0
 *
 * Allows GPP software to control when interrupts are generated.
 * Each interrupt can have up to 32 causes.  The enable/disable control's the
 * overall interrupt state. if the interrupt is disabled no causes will cause
 * an interrupt.
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpcon_set_irq_enable(struct fsl_mc_io *mc_io,
			 uint32_t cmd_flags,
			 uint16_t token,
			 uint8_t irq_index,
			 uint8_t en)
{
	struct dpcon_cmd_set_irq_enable *dpcon_cmd;
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPCON_CMDID_SET_IRQ_ENABLE,
					  cmd_flags,
					  token);
	dpcon_cmd = (struct dpcon_cmd_set_irq_enable *)cmd.params;
	dpcon_cmd->enable = en & DPCON_ENABLE;
	dpcon_cmd->irq_index = irq_index;

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpcon_get_irq_enable() - Get overall interrupt state.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPCON object
 * @irq_index:	The interrupt index to configure
 * @en:		Returned interrupt state - enable = 1, disable = 0
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpcon_get_irq_enable(struct fsl_mc_io *mc_io,
			 uint32_t cmd_flags,
			 uint16_t token,
			 uint8_t irq_index,
			 uint8_t *en)
{
	struct dpcon_cmd_get_irq_enable *dpcon_cmd;
	struct dpcon_rsp_get_irq_enable *dpcon_rsp;
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPCON_CMDID_GET_IRQ_ENABLE,
					  cmd_flags,
					  token);
	dpcon_cmd = (struct dpcon_cmd_get_irq_enable *)cmd.params;
	dpcon_cmd->irq_index = irq_index;

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	dpcon_rsp = (struct dpcon_rsp_get_irq_enable *)cmd.params;
	*en = dpcon_rsp->enabled & DPCON_ENABLE;

	return 0;
}

/**
 * dpcon_set_irq_mask() - Set interrupt mask.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPCON object
 * @irq_index:	The interrupt index to configure
 * @mask:	Event mask to trigger interrupt;
 *		each bit:
 *			0 = ignore event
 *			1 = consider event for asserting IRQ
 *
 * Every interrupt can have up to 32 causes and the interrupt model supports
 * masking/unmasking each cause independently
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpcon_set_irq_mask(struct fsl_mc_io *mc_io,
		       uint32_t cmd_flags,
		       uint16_t token,
		       uint8_t irq_index,
		       uint32_t mask)
{
	struct dpcon_cmd_set_irq_mask *dpcon_cmd;
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPCON_CMDID_SET_IRQ_MASK,
					  cmd_flags,
					  token);
	dpcon_cmd = (struct dpcon_cmd_set_irq_mask *)cmd.params;
	dpcon_cmd->mask = cpu_to_le32(mask);
	dpcon_cmd->irq_index = irq_index;

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpcon_get_irq_mask() - Get interrupt mask.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPCON object
 * @irq_index:	The interrupt index to configure
 * @mask:	Returned event mask to trigger interrupt
 *
 * Every interrupt can have up to 32 causes and the interrupt model supports
 * masking/unmasking each cause independently
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpcon_get_irq_mask(struct fsl_mc_io *mc_io,
		       uint32_t cmd_flags,
		       uint16_t token,
		       uint8_t irq_index,
		       uint32_t *mask)
{
	struct dpcon_cmd_get_irq_mask *dpcon_cmd;
	struct dpcon_rsp_get_irq_mask *dpcon_rsp;
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPCON_CMDID_GET_IRQ_MASK,
					  cmd_flags,
					  token);
	dpcon_cmd = (struct dpcon_cmd_get_irq_mask *)cmd.params;
	dpcon_cmd->irq_index = irq_index;

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	dpcon_rsp = (struct dpcon_rsp_get_irq_mask *)cmd.params;
	*mask = le32_to_cpu(dpcon_rsp->mask);

	return 0;
}

/**
 * dpcon_get_irq_status() - Get the current status of any pending interrupts.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPCON object
 * @irq_index:	The interrupt index to configure
 * @status:	interrupts status - one bit per cause:
 *			0 = no interrupt pending
 *			1 = interrupt pending
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpcon_get_irq_status(struct fsl_mc_io *mc_io,
			 uint32_t cmd_flags,
			 uint16_t token,
			 uint8_t irq_index,
			 uint32_t *status)
{
	struct dpcon_cmd_get_irq_status *dpcon_cmd;
	struct dpcon_rsp_get_irq_status *dpcon_rsp;
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPCON_CMDID_GET_IRQ_STATUS,
					  cmd_flags,
					  token);
	dpcon_cmd = (struct dpcon_cmd_get_irq_status *)cmd.params;
	dpcon_cmd->status = cpu_to_le32(*status);
	dpcon_cmd->irq_index = irq_index;

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	dpcon_rsp = (struct dpcon_rsp_get_irq_status *)cmd.params;
	*status = le32_to_cpu(dpcon_rsp->status);

	return 0;
}

/**
 * dpcon_clear_irq_status() - Clear a pending interrupt's status
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPCON object
 * @irq_index:	The interrupt index to configure
 * @status:	bits to clear (W1C) - one bit per cause:
 *			0 = don't change
 *			1 = clear status bit
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpcon_clear_irq_status(struct fsl_mc_io *mc_io,
			   uint32_t cmd_flags,
			   uint16_t token,
			   uint8_t irq_index,
			   uint32_t status)
{
	struct dpcon_cmd_clear_irq_status *dpcon_cmd;
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPCON_CMDID_CLEAR_IRQ_STATUS,
					  cmd_flags,
					  token);
	dpcon_cmd = (struct dpcon_cmd_clear_irq_status *)cmd.params;
	dpcon_cmd->status = cpu_to_le32(status);
	dpcon_cmd->irq_index = irq_index;

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpcon_get_attributes() - Retrieve DPCON attributes.
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPCON object
 * @attr:	Object's attributes
 *
 * Return:	'0' on Success; Error code otherwise.
 */
int dpcon_get_attributes(struct fsl_mc_io *mc_io,
			 uint32_t cmd_flags,
			 uint16_t token,
			 struct dpcon_attr *attr)
{
	struct dpcon_rsp_get_attr *dpcon_rsp;
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPCON_CMDID_GET_ATTR,
					  cmd_flags,
					  token);

	/* send command to mc*/
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	dpcon_rsp = (struct dpcon_rsp_get_attr *)cmd.params;
	attr->id = le32_to_cpu(dpcon_rsp->id);
	attr->qbman_ch_id = le16_to_cpu(dpcon_rsp->qbman_ch_id);
	attr->num_priorities = dpcon_rsp->num_priorities;

	return 0;
}

/**
 * dpcon_set_notification() - Set DPCON notification destination
 * @mc_io:	Pointer to MC portal's I/O object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @token:	Token of DPCON object
 * @cfg:	Notification parameters
 *
 * Return:	'0' on Success; Error code otherwise
 */
int dpcon_set_notification(struct fsl_mc_io *mc_io,
			   uint32_t cmd_flags,
			   uint16_t token,
			   struct dpcon_notification_cfg *cfg)
{
	struct dpcon_cmd_set_notification *dpcon_cmd;
	struct mc_command cmd = { 0 };

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPCON_CMDID_SET_NOTIFICATION,
					  cmd_flags,
					  token);
	dpcon_cmd = (struct dpcon_cmd_set_notification *)cmd.params;
	dpcon_cmd->dpio_id = cpu_to_le32(cfg->dpio_id);
	dpcon_cmd->priority = cfg->priority;
	dpcon_cmd->user_ctx = cpu_to_le64(cfg->user_ctx);

	/* send command to mc*/
	return mc_send_command(mc_io, &cmd);
}

/**
 * dpcon_get_api_version - Get Data Path Concentrator API version
 * @mc_io:	Pointer to MC portal's DPCON object
 * @cmd_flags:	Command flags; one or more of 'MC_CMD_FLAG_'
 * @major_ver:	Major version of DPCON API
 * @minor_ver:	Minor version of DPCON API
 *
 * Return:	'0' on Success; Error code otherwise
 */
int dpcon_get_api_version(struct fsl_mc_io *mc_io,
			  uint32_t cmd_flags,
			  uint16_t *major_ver,
			  uint16_t *minor_ver)
{
	struct dpcon_rsp_get_api_version *rsp_params;
	struct mc_command cmd = { 0 };
	int err;

	/* prepare command */
	cmd.header = mc_encode_cmd_header(DPCON_CMDID_GET_API_VERSION,
					  cmd_flags, 0);

	/* send command to mc */
	err = mc_send_command(mc_io, &cmd);
	if (err)
		return err;

	/* retrieve response parameters */
	rsp_params = (struct dpcon_rsp_get_api_version *)cmd.params;
	*major_ver = le16_to_cpu(rsp_params->major);
	*minor_ver = le16_to_cpu(rsp_params->minor);

	return 0;
}
