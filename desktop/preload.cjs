'use strict';

const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('desktop', Object.freeze({
  getConfig: () => ipcRenderer.invoke('desktop:get-config'),
  connect: serverUrl => ipcRenderer.invoke('desktop:connect', serverUrl),
  onStatus: callback => {
    if (typeof callback !== 'function') return () => {};
    const listener = (_event, status) => callback(status);
    ipcRenderer.on('desktop:status', listener);
    return () => ipcRenderer.removeListener('desktop:status', listener);
  },
}));
