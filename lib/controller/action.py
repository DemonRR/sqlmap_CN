#!/usr/bin/env python

"""
版权所有 (c) 2006-2024 sqlmap 开发者 (https://sqlmap.org/)
详见 'LICENSE' 文件获取复制权限信息
"""

from lib.controller.handler import setHandler
from lib.core.common import Backend
from lib.core.common import Format
from lib.core.data import conf
from lib.core.data import kb
from lib.core.data import logger
from lib.core.data import paths
from lib.core.enums import CONTENT_TYPE
from lib.core.exception import SqlmapNoneDataException
from lib.core.exception import SqlmapUnsupportedDBMSException
from lib.core.settings import SUPPORTED_DBMS
from lib.utils.brute import columnExists
from lib.utils.brute import fileExists
from lib.utils.brute import tableExists

def action():
    """
    此函数利用受影响 URL 参数中的 SQL 注入，并尝试从后端数据库管理系统或操作系统中提取请求的数据（如果可能）。
    """

    # 首先，我们需要识别后端数据库管理系统，以便继续进行注入
    setHandler()

    if not Backend.getDbms() or not conf.dbmsHandler:
        htmlParsed = Format.getErrorParsedDBMSes()

        errMsg = "sqlmap 无法识别后端数据库管理系统"

        if htmlParsed:
            errMsg += "，但根据 HTML 错误页面，可能的后端数据库管理系统是 %s" % htmlParsed

        if htmlParsed and htmlParsed.lower() in SUPPORTED_DBMS:
            errMsg += "。请不要手动指定后端数据库管理系统，sqlmap 会自动为您识别"
        elif kb.nullConnection:
            errMsg += "。您可以尝试在不使用优化参数 '%s' 的情况下重新运行" % ("-o" if conf.optimize else "--null-connection")

        raise SqlmapUnsupportedDBMSException(errMsg)

    conf.dumper.singleString(conf.dbmsHandler.getFingerprint())

    kb.fingerprinted = True

    # 枚举选项
    if conf.getBanner:
        conf.dumper.banner(conf.dbmsHandler.getBanner())

    if conf.getCurrentUser:
        conf.dumper.currentUser(conf.dbmsHandler.getCurrentUser())

    if conf.getCurrentDb:
        conf.dumper.currentDb(conf.dbmsHandler.getCurrentDb())

    if conf.getHostname:
        conf.dumper.hostname(conf.dbmsHandler.getHostname())

    if conf.isDba:
        conf.dumper.dba(conf.dbmsHandler.isDba())

    if conf.getUsers:
        conf.dumper.users(conf.dbmsHandler.getUsers())

    if conf.getStatements:
        conf.dumper.statements(conf.dbmsHandler.getStatements())

    if conf.getPasswordHashes:
        try:
            conf.dumper.userSettings("数据库用户密码哈希", conf.dbmsHandler.getPasswordHashes(), "密码哈希", CONTENT_TYPE.PASSWORDS)
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.getPrivileges:
        try:
            conf.dumper.userSettings("数据库用户权限", conf.dbmsHandler.getPrivileges(), "权限", CONTENT_TYPE.PRIVILEGES)
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.getRoles:
        try:
            conf.dumper.userSettings("数据库用户角色", conf.dbmsHandler.getRoles(), "角色", CONTENT_TYPE.ROLES)
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.getDbs:
        try:
            conf.dumper.dbs(conf.dbmsHandler.getDbs())
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.getTables:
        try:
            conf.dumper.dbTables(conf.dbmsHandler.getTables())
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.commonTables:
        try:
            conf.dumper.dbTables(tableExists(paths.COMMON_TABLES))
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.getSchema:
        try:
            conf.dumper.dbTableColumns(conf.dbmsHandler.getSchema(), CONTENT_TYPE.SCHEMA)
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.getColumns:
        try:
            conf.dumper.dbTableColumns(conf.dbmsHandler.getColumns(), CONTENT_TYPE.COLUMNS)
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.getCount:
        try:
            conf.dumper.dbTablesCount(conf.dbmsHandler.getCount())
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.commonColumns:
        try:
            conf.dumper.dbTableColumns(columnExists(paths.COMMON_COLUMNS))
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.dumpTable:
        try:
            conf.dbmsHandler.dumpTable()
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.dumpAll:
        try:
            conf.dbmsHandler.dumpAll()
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.search:
        try:
            conf.dbmsHandler.search()
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    if conf.sqlQuery:
        for query in conf.sqlQuery.strip(';').split(';'):
            query = query.strip()
            if query:
                conf.dumper.sqlQuery(query, conf.dbmsHandler.sqlQuery(query))

    if conf.sqlShell:
        conf.dbmsHandler.sqlShell()

    if conf.sqlFile:
        conf.dbmsHandler.sqlFile()

    # 用户自定义函数选项
    if conf.udfInject:
        conf.dbmsHandler.udfInjectCustom()

    # 文件系统选项
    if conf.fileRead:
        conf.dumper.rFile(conf.dbmsHandler.readFile(conf.fileRead))

    if conf.fileWrite:
        conf.dbmsHandler.writeFile(conf.fileWrite, conf.fileDest, conf.fileWriteType)

    if conf.commonFiles:
        try:
            conf.dumper.rFile(fileExists(paths.COMMON_FILES))
        except SqlmapNoneDataException as ex:
            logger.critical(ex)
        except:
            raise

    # 操作系统选项
    if conf.osCmd:
        conf.dbmsHandler.osCmd()

    if conf.osShell:
        conf.dbmsHandler.osShell()

    if conf.osPwn:
        conf.dbmsHandler.osPwn()

    if conf.osSmb:
        conf.dbmsHandler.osSmb()

    if conf.osBof:
        conf.dbmsHandler.osBof()

    # Windows 注册表选项
    if conf.regRead:
        conf.dumper.registerValue(conf.dbmsHandler.regRead())

    if conf.regAdd:
        conf.dbmsHandler.regAdd()

    if conf.regDel:
        conf.dbmsHandler.regDel()

    # 其他选项
    if conf.cleanup:
        conf.dbmsHandler.cleanup()

    if conf.direct:
        conf.dbmsConnector.close()
