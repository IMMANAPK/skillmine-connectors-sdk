// ============================================
// PLUGIN MANAGER - Extensibility Framework
// ============================================

import { EventEmitter } from 'events'

/**
 * Manages external plugins and extensions for the SDK.
 */
export class PluginManager extends EventEmitter {
    private plugins: Map<string, any> = new Map()

    constructor() {
        super()
    }

    /**
     * Register a new plugin
     */
    public registerPlugin(name: string, plugin: any): void {
        this.plugins.set(name, plugin)
        this.emit('plugin:registered', { name })
    }

    /**
     * Get a registered plugin
     */
    public getPlugin(name: string): any {
        return this.plugins.get(name)
    }
}

export const pluginManager = new PluginManager()
