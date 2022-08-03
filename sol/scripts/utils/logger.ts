import { Logger, TLogLevelName } from 'tslog';

const LOGGER_NAME = 'targetChainProxy';
const LOGGER_LEVEL: TLogLevelName = 'debug';

export const logger = new Logger({ name: LOGGER_NAME, minLevel: LOGGER_LEVEL });

export const setLogger = (name: string, minLevelString: string) => {
    const minLevel: TLogLevelName = minLevelString ? minLevelString as TLogLevelName : 'info';
    process.env.CROSS_CHAIN_LOG_LEVEL = minLevelString;
    process.env.CROSS_CHAIN_LOGGER_NAME = name;

    logger.setSettings({ minLevel, name });
};