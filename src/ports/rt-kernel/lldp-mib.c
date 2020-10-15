/*********************************************************************
 *        _       _         _
 *  _ __ | |_  _ | |  __ _ | |__   ___
 * | '__|| __|(_)| | / _` || '_ \ / __|
 * | |   | |_  _ | || (_| || |_) |\__ \
 * |_|    \__|(_)|_| \__,_||_.__/ |___/
 *
 * www.rt-labs.com
 * Copyright 2020 rt-labs AB, Sweden.
 *
 * This software is dual-licensed under GPLv3 and a commercial
 * license. See the file LICENSE.md distributed with this software for
 * full license information.
 ********************************************************************/

#include "lldp-mib.h"

#include "options.h"
#include "pnet_api.h"
#include "osal.h"
#include "osal_log.h"
#include "pnal.h"
#include "pf_types.h"
#include "pf_snmp.h"
#include "pnal_snmp.h"
#include "rowindex.h"

#include <string.h>

/*
Generated by LwipMibCompiler
*/

#include "lwip/apps/snmp_opts.h"
#if LWIP_SNMP

#include "lldp-mib.h"
#include "lwip/apps/snmp.h"
#include "lwip/apps/snmp_core.h"
#include "lwip/apps/snmp_scalar.h"
#include "lwip/apps/snmp_table.h"

/* --- lldpConfiguration 1.0.8802.1.1.2.1.1
 * ----------------------------------------------------- */

static snmp_err_t lldpconfigmanaddrtable_get_instance (
   const u32_t * column,
   const u32_t * row_oid,
   u8_t row_oid_len,
   struct snmp_node_instance * cell_instance);
static snmp_err_t lldpconfigmanaddrtable_get_next_instance (
   const u32_t * column,
   struct snmp_obj_id * row_oid,
   struct snmp_node_instance * cell_instance);
static s16_t lldpconfigmanaddrtable_get_value (
   struct snmp_node_instance * cell_instance,
   void * value);
static const struct snmp_table_col_def lldpconfigmanaddrtable_columns[] = {
   {1,
    SNMP_ASN1_TYPE_OCTET_STRING,
    SNMP_NODE_INSTANCE_READ_ONLY}, /* lldpConfigManAddrPortsTxEnable
                                    */
};
static const struct snmp_table_node lldpconfigmanaddrtable = SNMP_TABLE_CREATE (
   7,
   lldpconfigmanaddrtable_columns,
   lldpconfigmanaddrtable_get_instance,
   lldpconfigmanaddrtable_get_next_instance,
   lldpconfigmanaddrtable_get_value,
   NULL,
   NULL);

static const struct snmp_node * const lldpconfiguration_subnodes[] = {
   &lldpconfigmanaddrtable.node.node};
static const struct snmp_tree_node lldpconfiguration_treenode =
   SNMP_CREATE_TREE_NODE (1, lldpconfiguration_subnodes);

/* --- lldpLocalSystemData 1.0.8802.1.1.2.1.3
 * ----------------------------------------------------- */
static s16_t lldplocalsystemdata_treenode_get_value (
   struct snmp_node_instance * instance,
   void * value);
static const struct snmp_scalar_node lldplocchassisidsubtype_scalar =
   SNMP_SCALAR_CREATE_NODE_READONLY (
      1,
      SNMP_ASN1_TYPE_INTEGER,
      lldplocalsystemdata_treenode_get_value);

static const struct snmp_scalar_node lldplocchassisid_scalar =
   SNMP_SCALAR_CREATE_NODE_READONLY (
      2,
      SNMP_ASN1_TYPE_OCTET_STRING,
      lldplocalsystemdata_treenode_get_value);

static snmp_err_t lldplocporttable_get_instance (
   const u32_t * column,
   const u32_t * row_oid,
   u8_t row_oid_len,
   struct snmp_node_instance * cell_instance);
static snmp_err_t lldplocporttable_get_next_instance (
   const u32_t * column,
   struct snmp_obj_id * row_oid,
   struct snmp_node_instance * cell_instance);
static s16_t lldplocporttable_get_value (
   struct snmp_node_instance * cell_instance,
   void * value);
static const struct snmp_table_col_def lldplocporttable_columns[] = {
   {2,
    SNMP_ASN1_TYPE_INTEGER,
    SNMP_NODE_INSTANCE_READ_ONLY}, /* lldpLocPortIdSubtype
                                    */
   {3,
    SNMP_ASN1_TYPE_OCTET_STRING,
    SNMP_NODE_INSTANCE_READ_ONLY}, /* lldpLocPortId
                                    */
   {4,
    SNMP_ASN1_TYPE_OCTET_STRING,
    SNMP_NODE_INSTANCE_READ_ONLY}, /* lldpLocPortDesc
                                    */
};
static const struct snmp_table_node lldplocporttable = SNMP_TABLE_CREATE (
   7,
   lldplocporttable_columns,
   lldplocporttable_get_instance,
   lldplocporttable_get_next_instance,
   lldplocporttable_get_value,
   NULL,
   NULL);

static snmp_err_t lldplocmanaddrtable_get_instance (
   const u32_t * column,
   const u32_t * row_oid,
   u8_t row_oid_len,
   struct snmp_node_instance * cell_instance);
static snmp_err_t lldplocmanaddrtable_get_next_instance (
   const u32_t * column,
   struct snmp_obj_id * row_oid,
   struct snmp_node_instance * cell_instance);
static s16_t lldplocmanaddrtable_get_value (
   struct snmp_node_instance * cell_instance,
   void * value);
static const struct snmp_table_col_def lldplocmanaddrtable_columns[] = {
   {3,
    SNMP_ASN1_TYPE_INTEGER,
    SNMP_NODE_INSTANCE_READ_ONLY}, /* lldpLocManAddrLen
                                    */
   {4,
    SNMP_ASN1_TYPE_INTEGER,
    SNMP_NODE_INSTANCE_READ_ONLY}, /* lldpLocManAddrIfSubtype
                                    */
   {5,
    SNMP_ASN1_TYPE_INTEGER,
    SNMP_NODE_INSTANCE_READ_ONLY}, /* lldpLocManAddrIfId
                                    */
};
static const struct snmp_table_node lldplocmanaddrtable = SNMP_TABLE_CREATE (
   8,
   lldplocmanaddrtable_columns,
   lldplocmanaddrtable_get_instance,
   lldplocmanaddrtable_get_next_instance,
   lldplocmanaddrtable_get_value,
   NULL,
   NULL);

static const struct snmp_node * const lldplocalsystemdata_subnodes[] = {
   &lldplocchassisidsubtype_scalar.node.node,
   &lldplocchassisid_scalar.node.node,
   &lldplocporttable.node.node,
   &lldplocmanaddrtable.node.node};
static const struct snmp_tree_node lldplocalsystemdata_treenode =
   SNMP_CREATE_TREE_NODE (3, lldplocalsystemdata_subnodes);

/* --- lldpRemoteSystemsData 1.0.8802.1.1.2.1.4
 * ----------------------------------------------------- */
static snmp_err_t lldpremtable_get_instance (
   const u32_t * column,
   const u32_t * row_oid,
   u8_t row_oid_len,
   struct snmp_node_instance * cell_instance);
static snmp_err_t lldpremtable_get_next_instance (
   const u32_t * column,
   struct snmp_obj_id * row_oid,
   struct snmp_node_instance * cell_instance);
static s16_t lldpremtable_get_value (
   struct snmp_node_instance * cell_instance,
   void * value);
static const struct snmp_table_col_def lldpremtable_columns[] = {
   {4,
    SNMP_ASN1_TYPE_INTEGER,
    SNMP_NODE_INSTANCE_READ_ONLY}, /* lldpRemChassisIdSubtype
                                    */
   {5,
    SNMP_ASN1_TYPE_OCTET_STRING,
    SNMP_NODE_INSTANCE_READ_ONLY}, /* lldpRemChassisId
                                    */
   {6,
    SNMP_ASN1_TYPE_INTEGER,
    SNMP_NODE_INSTANCE_READ_ONLY}, /* lldpRemPortIdSubtype
                                    */
   {7,
    SNMP_ASN1_TYPE_OCTET_STRING,
    SNMP_NODE_INSTANCE_READ_ONLY}, /* lldpRemPortId
                                    */
   {8,
    SNMP_ASN1_TYPE_OCTET_STRING,
    SNMP_NODE_INSTANCE_READ_ONLY}, /* lldpRemPortDesc
                                    */
};
static const struct snmp_table_node lldpremtable = SNMP_TABLE_CREATE (
   1,
   lldpremtable_columns,
   lldpremtable_get_instance,
   lldpremtable_get_next_instance,
   lldpremtable_get_value,
   NULL,
   NULL);

static snmp_err_t lldpremmanaddrtable_get_instance (
   const u32_t * column,
   const u32_t * row_oid,
   u8_t row_oid_len,
   struct snmp_node_instance * cell_instance);
static snmp_err_t lldpremmanaddrtable_get_next_instance (
   const u32_t * column,
   struct snmp_obj_id * row_oid,
   struct snmp_node_instance * cell_instance);
static s16_t lldpremmanaddrtable_get_value (
   struct snmp_node_instance * cell_instance,
   void * value);
static const struct snmp_table_col_def lldpremmanaddrtable_columns[] = {
   {3,
    SNMP_ASN1_TYPE_INTEGER,
    SNMP_NODE_INSTANCE_READ_ONLY}, /* lldpRemManAddrIfSubtype
                                    */
   {4,
    SNMP_ASN1_TYPE_INTEGER,
    SNMP_NODE_INSTANCE_READ_ONLY}, /* lldpRemManAddrIfId
                                    */
};
static const struct snmp_table_node lldpremmanaddrtable = SNMP_TABLE_CREATE (
   2,
   lldpremmanaddrtable_columns,
   lldpremmanaddrtable_get_instance,
   lldpremmanaddrtable_get_next_instance,
   lldpremmanaddrtable_get_value,
   NULL,
   NULL);

static const struct snmp_node * const lldpremotesystemsdata_subnodes[] = {
   &lldpremtable.node.node,
   &lldpremmanaddrtable.node.node};
static const struct snmp_tree_node lldpremotesystemsdata_treenode =
   SNMP_CREATE_TREE_NODE (4, lldpremotesystemsdata_subnodes);

/* --- lldpObjects 1.0.8802.1.1.2.1
 * ----------------------------------------------------- */
static const struct snmp_node * const lldpobjects_subnodes[] = {
   &lldpconfiguration_treenode.node,
   &lldplocalsystemdata_treenode.node,
   &lldpremotesystemsdata_treenode.node};
static const struct snmp_tree_node lldpobjects_treenode =
   SNMP_CREATE_TREE_NODE (1, lldpobjects_subnodes);

/* --- lldpMIB  ----------------------------------------------------- */
static const struct snmp_node * const lldpmib_subnodes[] = {
   &lldpobjects_treenode.node};
static const struct snmp_tree_node lldpmib_root =
   SNMP_CREATE_TREE_NODE (2, lldpmib_subnodes);
static const u32_t lldpmib_base_oid[] = {1, 0, 8802, 1, 1, 2};
const struct snmp_mib lldpmib = {
   lldpmib_base_oid,
   LWIP_ARRAYSIZE (lldpmib_base_oid),
   &lldpmib_root.node};

/*
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
LWIP MIB generator - preserved section begin
Code below is preserved on regeneration. Remove these comment lines to
regenerate code.
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

/* --- lldpConfiguration 1.0.8802.1.1.2.1.1
 * ----------------------------------------------------- */

/**
 * Get cell in table lldpConfigManAddrTable
 *
 * Called when an SNMP Get request is received for this table.
 * If cell is found, the SNMP stack may call the corresponding get_value()
 * function below to retrieve the actual value contained in the cell.
 *
 * @param column           In:    Column index for the cell.
 * @param row_oid          In:    Row index (array) for the cell.
 * @param row_oid_len      In:    The number of elements in the row index array.
 * @param cell_instance    InOut: Cell instance (containing meta-data).
 * @return  SNMP_ERR_NOERROR if cell was found,
 *          SNMP_ERR_NOSUCHINSTANCE otherwise.
 */
static snmp_err_t lldpconfigmanaddrtable_get_instance (
   const u32_t * column,
   const u32_t * row_oid,
   u8_t row_oid_len,
   struct snmp_node_instance * cell_instance)
{
   int interface = rowindex_match_with_local_interface (row_oid, row_oid_len);
   if (interface == 0)
   {
      return SNMP_ERR_NOSUCHINSTANCE;
   }
   else
   {
      return SNMP_ERR_NOERROR;
   }
}

/**
 * Get next cell in table lldpConfigManAddrTable.
 *
 * Called when an SNMP GetNext request is received for this table.
 * If cell is found, the SNMP stack may call the corresponding get_value()
 * function below to retrieve the actual value contained in the cell.
 *
 * @param column           In:    Column index for the cell.
 * @param row_oid          InOut: Row index for the cell.
 * @param cell_instance    InOut: Cell instance (containing meta-data).
 * @return  SNMP_ERR_NOERROR if cell was found,
 *          SNMP_ERR_NOSUCHINSTANCE otherwise.
 */
static snmp_err_t lldpconfigmanaddrtable_get_next_instance (
   const u32_t * column,
   struct snmp_obj_id * row_oid,
   struct snmp_node_instance * cell_instance)
{
   int interface = rowindex_update_with_next_local_interface (row_oid);
   if (interface == 0)
   {
      return SNMP_ERR_NOSUCHINSTANCE;
   }
   else
   {
      return SNMP_ERR_NOERROR;
   }
}

/**
 * Get value at cell in table lldpConfigManAddrTable.
 *
 * Called when an SNMP Get or GetNext request is received for this table.
 * The cell was previously identified in a call to get_instance() or
 * get_next_instance().
 *
 * @param cell_instance    In:    Cell instance (containing meta-data).
 * @param value            Out:   Value to be returned in response.
 * @return  Size of returned value, in bytes.
 *          0 if error occurred.
 */
static s16_t lldpconfigmanaddrtable_get_value (
   struct snmp_node_instance * cell_instance,
   void * value)
{
   s16_t value_len;

   switch (SNMP_TABLE_GET_COLUMN_FROM_OID (cell_instance->instance_oid.id))
   {
   case 1:
   {
      /* lldpConfigManAddrPortsTxEnable */
      pf_lldp_port_list_t port_list;

      pf_snmp_get_port_list (pnal_snmp.net, &port_list);
      memcpy (value, port_list.ports, sizeof (port_list.ports));
      value_len = sizeof (port_list.ports);
   }
   break;
   default:
   {
      /* TODO: Use osal logging */
      LWIP_DEBUGF (
         SNMP_MIB_DEBUG,
         ("lldpconfigmanaddrtable_get_value(): unknown id: %" S32_F "\n",
          SNMP_TABLE_GET_COLUMN_FROM_OID (cell_instance->instance_oid.id)));
      value_len = 0;
   }
   break;
   }
   return value_len;
}

/* --- lldpLocalSystemData 1.0.8802.1.1.2.1.3
 * ----------------------------------------------------- */

/**
 * Get cell in table lldpLocPortTable
 *
 * Called when an SNMP Get request is received for this table.
 * If cell is found, the SNMP stack may call the corresponding get_value()
 * function below to retrieve the actual value contained in the cell.
 *
 * @param column           In:    Column index for the cell.
 * @param row_oid          In:    Row index (array) for the cell.
 * @param row_oid_len      In:    The number of elements in the row index array.
 * @param cell_instance    InOut: Cell instance (containing meta-data).
 * @return  SNMP_ERR_NOERROR if cell was found,
 *          SNMP_ERR_NOSUCHINSTANCE otherwise.
 */
static snmp_err_t lldplocporttable_get_instance (
   const u32_t * column,
   const u32_t * row_oid,
   u8_t row_oid_len,
   struct snmp_node_instance * cell_instance)
{
   int port = rowindex_match_with_local_port (row_oid, row_oid_len);
   if (port == 0)
   {
      return SNMP_ERR_NOSUCHINSTANCE;
   }
   else
   {
      cell_instance->reference.s32 = port;
      return SNMP_ERR_NOERROR;
   }
}

/**
 * Get next cell in table lldpLocPortTable.
 *
 * Called when an SNMP GetNext request is received for this table.
 * If cell is found, the SNMP stack may call the corresponding get_value()
 * function below to retrieve the actual value contained in the cell.
 *
 * @param column           In:    Column index for the cell.
 * @param row_oid          InOut: Row index for the cell.
 * @param cell_instance    InOut: Cell instance (containing meta-data).
 * @return  SNMP_ERR_NOERROR if cell was found,
 *          SNMP_ERR_NOSUCHINSTANCE otherwise.
 */
static snmp_err_t lldplocporttable_get_next_instance (
   const u32_t * column,
   struct snmp_obj_id * row_oid,
   struct snmp_node_instance * cell_instance)
{
   int port = rowindex_update_with_next_local_port (row_oid);
   if (port == 0)
   {
      return SNMP_ERR_NOSUCHINSTANCE;
   }
   else
   {
      cell_instance->reference.s32 = port;
      return SNMP_ERR_NOERROR;
   }
}

/**
 * Get value at cell in table lldpLocPortTable.
 *
 * Called when an SNMP Get or GetNext request is received for this table.
 * The cell was previously identified in a call to get_instance() or
 * get_next_instance().
 *
 * @param cell_instance    In:    Cell instance (containing meta-data).
 * @param value            Out:   Value to be returned in response.
 * @return  Size of returned value, in bytes.
 *          0 if error occurred.
 */
static s16_t lldplocporttable_get_value (
   struct snmp_node_instance * cell_instance,
   void * value)
{
   s16_t value_len;
   int port = cell_instance->reference.s32;

   switch (SNMP_TABLE_GET_COLUMN_FROM_OID (cell_instance->instance_oid.id))
   {
   case 2:
   {
      /* lldpLocPortIdSubtype */
      s32_t * v = (s32_t *)value;
      pf_lldp_port_id_t port_id;

      pf_snmp_get_port_id (pnal_snmp.net, port, &port_id);
      *v = port_id.subtype;
      value_len = sizeof (s32_t);
   }
   break;
   case 3:
   {
      /* lldpLocPortId */
      char * v = (char *)value;
      pf_lldp_port_id_t port_id;

      pf_snmp_get_port_id (pnal_snmp.net, port, &port_id);
      value_len = port_id.len;
      strncpy (v, port_id.string, SNMP_MAX_VALUE_SIZE);
   }
   break;
   case 4:
   {
      /* lldpLocPortDesc */
      char * v = (char *)value;
      pf_lldp_port_description_t port_desc;

      pf_snmp_get_port_description (pnal_snmp.net, port, &port_desc);
      value_len = port_desc.len;
      strncpy (v, port_desc.string, SNMP_MAX_VALUE_SIZE);
   }
   break;
   default:
   {
      LWIP_DEBUGF (
         SNMP_MIB_DEBUG,
         ("lldplocporttable_get_value(): unknown id: %" S32_F "\n",
          SNMP_TABLE_GET_COLUMN_FROM_OID (cell_instance->instance_oid.id)));
      value_len = 0;
   }
   break;
   }
   return value_len;
}

/**
 * Get cell in table lldpLocManAddrTable.
 *
 * Called when an SNMP Get request is received for this table.
 * If cell is found, the SNMP stack may call the corresponding get_value()
 * function below to retrieve the actual value contained in the cell.
 *
 * @param column           In:    Column index for the cell.
 * @param row_oid          In:    Row index (array) for the cell.
 * @param row_oid_len      In:    The number of elements in the row index array.
 * @param cell_instance    InOut: Cell instance (containing meta-data).
 * @return  SNMP_ERR_NOERROR if cell was found,
 *          SNMP_ERR_NOSUCHINSTANCE otherwise.
 */
static snmp_err_t lldplocmanaddrtable_get_instance (
   const u32_t * column,
   const u32_t * row_oid,
   u8_t row_oid_len,
   struct snmp_node_instance * cell_instance)
{
   int interface = rowindex_match_with_local_interface (row_oid, row_oid_len);
   if (interface == 0)
   {
      return SNMP_ERR_NOSUCHINSTANCE;
   }
   else
   {
      return SNMP_ERR_NOERROR;
   }
}

/**
 * Get next cell in table lldpLocManAddrTable.
 *
 * Called when an SNMP GetNext request is received for this table.
 * If cell is found, the SNMP stack may call the corresponding get_value()
 * function below to retrieve the actual value contained in the cell.
 *
 * @param column           In:    Column index for the cell.
 * @param row_oid          InOut: Row index for the cell.
 * @param cell_instance    InOut: Cell instance (containing meta-data).
 * @return  SNMP_ERR_NOERROR if cell was found,
 *          SNMP_ERR_NOSUCHINSTANCE otherwise.
 */
static snmp_err_t lldplocmanaddrtable_get_next_instance (
   const u32_t * column,
   struct snmp_obj_id * row_oid,
   struct snmp_node_instance * cell_instance)
{
   int interface = rowindex_update_with_next_local_interface (row_oid);
   if (interface == 0)
   {
      return SNMP_ERR_NOSUCHINSTANCE;
   }
   else
   {
      return SNMP_ERR_NOERROR;
   }
}

/**
 * Get value at cell in table lldpLocManAddrTable.
 *
 * Called when an SNMP Get or GetNext request is received for this table.
 * The cell was previously identified in a call to get_instance() or
 * get_next_instance().
 *
 * @param cell_instance    In:    Cell instance (containing meta-data).
 * @param value            Out:   Value to be returned in response.
 * @return  Size of returned value, in bytes.
 *          0 if error occurred.
 */
static s16_t lldplocmanaddrtable_get_value (
   struct snmp_node_instance * cell_instance,
   void * value)
{
   s16_t value_len;

   switch (SNMP_TABLE_GET_COLUMN_FROM_OID (cell_instance->instance_oid.id))
   {
   case 3:
   {
      /* lldpLocManAddrLen */
      s32_t * v = (s32_t *)value;
      pf_lldp_management_address_t address;

      pf_snmp_get_management_address (pnal_snmp.net, &address);
      value_len = sizeof (s32_t);
      *v = address.len + 1;
   }
   break;
   case 4:
   {
      /* lldpLocManAddrIfSubtype */
      s32_t * v = (s32_t *)value;
      pf_lldp_management_port_index_t port_index;

      pf_snmp_get_management_port_index (pnal_snmp.net, &port_index);
      value_len = sizeof (s32_t);
      *v = port_index.subtype;
   }
   break;
   case 5:
   {
      /* lldpLocManAddrIfId */
      s32_t * v = (s32_t *)value;
      pf_lldp_management_port_index_t port_index;

      pf_snmp_get_management_port_index (pnal_snmp.net, &port_index);

      value_len = sizeof (s32_t);
      *v = port_index.index;
   }
   break;
   default:
   {
      LWIP_DEBUGF (
         SNMP_MIB_DEBUG,
         ("lldplocmanaddrtable_get_value(): unknown id: %" S32_F "\n",
          SNMP_TABLE_GET_COLUMN_FROM_OID (cell_instance->instance_oid.id)));
      value_len = 0;
   }
   break;
   }
   return value_len;
}

/**
 * Get value at top level cell in table lldpLocManAddrTable.
 *
 * Called when an SNMP Get or GetNext request is received for this table.
 * The cell was previously identified in a call to get_instance() or
 * get_next_instance().
 *
 * @param cell_instance    In:    Cell instance (containing meta-data).
 * @param value            Out:   Value to be returned in response.
 * @return  Size of returned value, in bytes.
 *          0 if error occurred.
 */
static s16_t lldplocalsystemdata_treenode_get_value (
   struct snmp_node_instance * instance,
   void * value)
{
   s16_t value_len;

   switch (instance->node->oid)
   {
   case 1:
   {
      /* lldpLocChassisIdSubtype */
      s32_t * v = (s32_t *)value;
      pf_lldp_chassis_id_t chassis_id;

      pf_snmp_get_chassis_id (pnal_snmp.net, &chassis_id);
      value_len = sizeof (s32_t);
      *v = chassis_id.subtype;
   }
   break;
   case 2:
   {
      /* lldpLocChassisId */
      u8_t * v = (u8_t *)value;
      pf_lldp_chassis_id_t chassis_id;

      pf_snmp_get_chassis_id (pnal_snmp.net, &chassis_id);
      value_len = chassis_id.len;
      if ((size_t)value_len > SNMP_MAX_VALUE_SIZE)
      {
         LWIP_DEBUGF (
            SNMP_MIB_DEBUG,
            ("value is to large (%u > %u)\n",
             (size_t)value_len,
             SNMP_MAX_VALUE_SIZE));
         value_len = 0;
      }
      else
      {
         memcpy (v, chassis_id.string, value_len);
      }
   }
   break;
   default:
   {
      LWIP_DEBUGF (
         SNMP_MIB_DEBUG,
         ("lldplocalsystemdata_treenode_get_value(): unknown id: %" S32_F "\n",
          instance->node->oid));
      value_len = 0;
   }
   break;
   }
   return value_len;
}

/* --- lldpRemoteSystemsData 1.0.8802.1.1.2.1.4
 * ----------------------------------------------------- */

/**
 * Get cell in table lldpRemTable
 *
 * Called when an SNMP Get request is received for this table.
 * If cell is found, the SNMP stack may call the corresponding get_value()
 * function below to retrieve the actual value contained in the cell.
 *
 * @param column           In:    Column index for the cell.
 * @param row_oid          In:    Row index (array) for the cell.
 * @param row_oid_len      In:    The number of elements in the row index array.
 * @param cell_instance    InOut: Cell instance (containing meta-data).
 * @return  SNMP_ERR_NOERROR if cell was found,
 *          SNMP_ERR_NOSUCHINSTANCE otherwise.
 */
static snmp_err_t lldpremtable_get_instance (
   const u32_t * column,
   const u32_t * row_oid,
   u8_t row_oid_len,
   struct snmp_node_instance * cell_instance)
{
   int port = rowindex_match_with_remote_device (row_oid, row_oid_len);
   if (port == 0)
   {
      return SNMP_ERR_NOSUCHINSTANCE;
   }
   else
   {
      cell_instance->reference.s32 = port;
      return SNMP_ERR_NOERROR;
   }
}

/**
 * Get next cell in table lldpRemTable.
 *
 * Called when an SNMP GetNext request is received for this table.
 * If cell is found, the SNMP stack may call the corresponding get_value()
 * function below to retrieve the actual value contained in the cell.
 *
 * @param column           In:    Column index for the cell.
 * @param row_oid          InOut: Row index for the cell.
 * @param cell_instance    InOut: Cell instance (containing meta-data).
 * @return  SNMP_ERR_NOERROR if cell was found,
 *          SNMP_ERR_NOSUCHINSTANCE otherwise.
 */
static snmp_err_t lldpremtable_get_next_instance (
   const u32_t * column,
   struct snmp_obj_id * row_oid,
   struct snmp_node_instance * cell_instance)
{
   int port = rowindex_update_with_next_remote_device (row_oid);
   if (port == 0)
   {
      return SNMP_ERR_NOSUCHINSTANCE;
   }
   else
   {
      cell_instance->reference.s32 = port;
      return SNMP_ERR_NOERROR;
   }
}

/**
 * Get value at cell in table lldpRemTable.
 *
 * Called when an SNMP Get or GetNext request is received for this table.
 * The cell was previously identified in a call to get_instance() or
 * get_next_instance().
 *
 * @param cell_instance    In:    Cell instance (containing meta-data).
 * @param value            Out:   Value to be returned in response.
 * @return  Size of returned value, in bytes.
 *          0 if error occurred.
 */
static s16_t lldpremtable_get_value (
   struct snmp_node_instance * cell_instance,
   void * value)
{
   s16_t value_len;
   int port = cell_instance->reference.s32;

   switch (SNMP_TABLE_GET_COLUMN_FROM_OID (cell_instance->instance_oid.id))
   {
   case 4:
   {
      /* lldpRemChassisIdSubtype */
      s32_t * v = (s32_t *)value;
      pf_lldp_chassis_id_t chassis_id;
      int error;

      error = pf_snmp_get_peer_chassis_id (pnal_snmp.net, port, &chassis_id);
      if (error)
      {
         value_len = 0;
      }
      else
      {
         value_len = sizeof (s32_t);
         *v = chassis_id.subtype;
      }
   }
   break;
   case 5:
   {
      /* lldpRemChassisId */
      u8_t * v = (u8_t *)value;
      pf_lldp_chassis_id_t chassis_id;
      int error;

      error = pf_snmp_get_peer_chassis_id (pnal_snmp.net, port, &chassis_id);
      value_len = chassis_id.len;
      if (error || (size_t)value_len > SNMP_MAX_VALUE_SIZE)
      {
         LWIP_DEBUGF (
            SNMP_MIB_DEBUG,
            ("value is to large (%u > %u)\n",
             (size_t)value_len,
             SNMP_MAX_VALUE_SIZE));
         value_len = 0;
      }
      else
      {
         memcpy (v, chassis_id.string, value_len);
      }
   }
   break;
   case 6:
   {
      /* lldpRemPortIdSubtype */
      s32_t * v = (s32_t *)value;
      pf_lldp_port_id_t port_id;
      int error;

      error = pf_snmp_get_peer_port_id (pnal_snmp.net, port, &port_id);
      value_len = sizeof (s32_t);
      if (error)
      {
         LWIP_DEBUGF (
            SNMP_MIB_DEBUG,
            ("value is to large (%u > %u)\n",
             (size_t)value_len,
             SNMP_MAX_VALUE_SIZE));
         value_len = 0;
      }
      else
      {
         *v = port_id.subtype;
      }
   }
   break;
   case 7:
   {
      /* lldpRemPortId */
      u8_t * v = (u8_t *)value;
      pf_lldp_port_id_t port_id;
      int error;

      error = pf_snmp_get_peer_port_id (pnal_snmp.net, port, &port_id);
      value_len = port_id.len;
      if (error || (size_t)value_len > SNMP_MAX_VALUE_SIZE)
      {
         LWIP_DEBUGF (
            SNMP_MIB_DEBUG,
            ("value is to large (%u > %u)\n",
             (size_t)value_len,
             SNMP_MAX_VALUE_SIZE));
         value_len = 0;
      }
      else
      {
         memcpy (v, port_id.string, value_len);
      }
   }
   break;
   case 8:
   {
      /* lldpRemPortDesc */
      char * v = (char *)value;
      pf_lldp_port_description_t port_desc;
      int error;

      error =
         pf_snmp_get_peer_port_description (pnal_snmp.net, port, &port_desc);
      value_len = port_desc.len;
      if (error || (size_t)value_len > SNMP_MAX_VALUE_SIZE)
      {
         LWIP_DEBUGF (
            SNMP_MIB_DEBUG,
            ("value is to large (%u > %u)\n",
             (size_t)value_len,
             SNMP_MAX_VALUE_SIZE));
         value_len = 0;
      }
      else
      {
         memcpy (v, port_desc.string, value_len);
      }
   }
   break;
   default:
   {
      LWIP_DEBUGF (
         SNMP_MIB_DEBUG,
         ("lldpremtable_get_value(): unknown id: %" S32_F "\n",
          SNMP_TABLE_GET_COLUMN_FROM_OID (cell_instance->instance_oid.id)));
      value_len = 0;
   }
   break;
   }
   return value_len;
}

/**
 * Get cell in table lldpRemManAddrTable
 *
 * Called when an SNMP Get request is received for this table.
 * If cell is found, the SNMP stack may call the corresponding get_value()
 * function below to retrieve the actual value contained in the cell.
 *
 * @param column           In:    Column index for the cell.
 * @param row_oid          In:    Row index (array) for the cell.
 * @param row_oid_len      In:    The number of elements in the row index array.
 * @param cell_instance    InOut: Cell instance (containing meta-data).
 * @return  SNMP_ERR_NOERROR if cell was found,
 *          SNMP_ERR_NOSUCHINSTANCE otherwise.
 */
static snmp_err_t lldpremmanaddrtable_get_instance (
   const u32_t * column,
   const u32_t * row_oid,
   u8_t row_oid_len,
   struct snmp_node_instance * cell_instance)
{
   int port = rowindex_match_with_remote_interface (row_oid, row_oid_len);
   if (port == 0)
   {
      return SNMP_ERR_NOSUCHINSTANCE;
   }
   else
   {
      cell_instance->reference.s32 = port;
      return SNMP_ERR_NOERROR;
   }
}

/**
 * Get next cell in table lldpConfigManAddrTable.
 *
 * Called when an SNMP GetNext request is received for this table.
 * If cell is found, the SNMP stack may call the corresponding get_value()
 * function below to retrieve the actual value contained in the cell.
 *
 * @param column           In:    Column index for the cell.
 * @param row_oid          InOut: Row index for the cell.
 * @param cell_instance    InOut: Cell instance (containing meta-data).
 * @return  SNMP_ERR_NOERROR if cell was found,
 *          SNMP_ERR_NOSUCHINSTANCE otherwise.
 */
static snmp_err_t lldpremmanaddrtable_get_next_instance (
   const u32_t * column,
   struct snmp_obj_id * row_oid,
   struct snmp_node_instance * cell_instance)
{
   int port = rowindex_update_with_next_remote_interface (row_oid);
   if (port == 0)
   {
      return SNMP_ERR_NOSUCHINSTANCE;
   }
   else
   {
      cell_instance->reference.s32 = port;
      return SNMP_ERR_NOERROR;
   }
}

/**
 * Get value at cell in table lldpConfigManAddrTable.
 *
 * Called when an SNMP Get or GetNext request is received for this table.
 * The cell was previously identified in a call to get_instance() or
 * get_next_instance().
 *
 * @param cell_instance    In:    Cell instance (containing meta-data).
 * @param value            Out:   Value to be returned in response.
 * @return  Size of returned value, in bytes.
 *          0 if error occurred.
 */
static s16_t lldpremmanaddrtable_get_value (
   struct snmp_node_instance * cell_instance,
   void * value)
{
   s16_t value_len;
   int port = cell_instance->reference.s32;

   switch (SNMP_TABLE_GET_COLUMN_FROM_OID (cell_instance->instance_oid.id))
   {
   case 3:
   {
      /* lldpRemManAddrIfSubtype */
      s32_t * v = (s32_t *)value;
      pf_lldp_management_port_index_t port_index;
      int error;

      error = pf_snmp_get_peer_management_port_index (
         pnal_snmp.net,
         port,
         &port_index);
      if (error)
      {
         value_len = 0;
      }
      else
      {
         value_len = sizeof (s32_t);
         *v = port_index.subtype;
      }
   }
   break;
   case 4:
   {
      /* lldpRemManAddrIfId */
      s32_t * v = (s32_t *)value;
      pf_lldp_management_port_index_t port_index;
      int error;

      error = pf_snmp_get_peer_management_port_index (
         pnal_snmp.net,
         port,
         &port_index);
      if (error)
      {
         value_len = 0;
      }
      else
      {
         value_len = sizeof (s32_t);
         *v = port_index.index;
      }
   }
   break;
   default:
   {
      LWIP_DEBUGF (
         SNMP_MIB_DEBUG,
         ("lldpremmanaddrtable_get_value(): unknown id: %" S32_F "\n",
          SNMP_TABLE_GET_COLUMN_FROM_OID (cell_instance->instance_oid.id)));
      value_len = 0;
   }
   break;
   }
   return value_len;
}

/* --- lldpObjects 1.0.8802.1.1.2.1
 * ----------------------------------------------------- */
/* --- lldpMIB  ----------------------------------------------------- */
#endif /* LWIP_SNMP */
