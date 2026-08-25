import { ResponseContext, RequestContext, HttpFile, HttpInfo } from '../http/http';
import { Configuration, ConfigurationOptions } from '../configuration'
import type { Middleware } from '../middleware';

import { ApiKeyResponse } from '../models/ApiKeyResponse';
import { BackendConfigRequest } from '../models/BackendConfigRequest';
import { BackendConfigResponse } from '../models/BackendConfigResponse';
import { BackendType } from '../models/BackendType';
import { CreateKeyRequest } from '../models/CreateKeyRequest';
import { DeleteKeyRequest } from '../models/DeleteKeyRequest';
import { ListKeyResponse } from '../models/ListKeyResponse';
import { ObjectResponse } from '../models/ObjectResponse';

import { ObservableBackendApi } from "./ObservableAPI";
import { BackendApiRequestFactory, BackendApiResponseProcessor} from "../apis/BackendApi";

export interface BackendApiGetBackendRequest {
}

export interface BackendApiPutBackendRequest {
    /**
     * 
     * @type BackendConfigRequest
     * @memberof BackendApiputBackend
     */
    backendConfigRequest: BackendConfigRequest
}

export class ObjectBackendApi {
    private api: ObservableBackendApi

    public constructor(configuration: Configuration, requestFactory?: BackendApiRequestFactory, responseProcessor?: BackendApiResponseProcessor) {
        this.api = new ObservableBackendApi(configuration, requestFactory, responseProcessor);
    }

    /**
     * @param param the request object
     */
    public getBackendWithHttpInfo(param: BackendApiGetBackendRequest = {}, options?: ConfigurationOptions): Promise<HttpInfo<BackendConfigResponse>> {
        return this.api.getBackendWithHttpInfo( options).toPromise();
    }

    /**
     * @param param the request object
     */
    public getBackend(param: BackendApiGetBackendRequest = {}, options?: ConfigurationOptions): Promise<BackendConfigResponse> {
        return this.api.getBackend( options).toPromise();
    }

    /**
     * @param param the request object
     */
    public putBackendWithHttpInfo(param: BackendApiPutBackendRequest, options?: ConfigurationOptions): Promise<HttpInfo<BackendConfigResponse>> {
        return this.api.putBackendWithHttpInfo(param.backendConfigRequest,  options).toPromise();
    }

    /**
     * @param param the request object
     */
    public putBackend(param: BackendApiPutBackendRequest, options?: ConfigurationOptions): Promise<BackendConfigResponse> {
        return this.api.putBackend(param.backendConfigRequest,  options).toPromise();
    }

}

import { ObservableKeysApi } from "./ObservableAPI";
import { KeysApiRequestFactory, KeysApiResponseProcessor} from "../apis/KeysApi";

export interface KeysApiCreateKeyRequest {
    /**
     * 
     * @type CreateKeyRequest
     * @memberof KeysApicreateKey
     */
    createKeyRequest: CreateKeyRequest
}

export interface KeysApiDeleteKeyRequest {
    /**
     * 
     * @type DeleteKeyRequest
     * @memberof KeysApideleteKey
     */
    deleteKeyRequest: DeleteKeyRequest
}

export interface KeysApiGetKeysRequest {
}

export class ObjectKeysApi {
    private api: ObservableKeysApi

    public constructor(configuration: Configuration, requestFactory?: KeysApiRequestFactory, responseProcessor?: KeysApiResponseProcessor) {
        this.api = new ObservableKeysApi(configuration, requestFactory, responseProcessor);
    }

    /**
     * Create a new API key
     * @param param the request object
     */
    public createKeyWithHttpInfo(param: KeysApiCreateKeyRequest, options?: ConfigurationOptions): Promise<HttpInfo<ApiKeyResponse>> {
        return this.api.createKeyWithHttpInfo(param.createKeyRequest,  options).toPromise();
    }

    /**
     * Create a new API key
     * @param param the request object
     */
    public createKey(param: KeysApiCreateKeyRequest, options?: ConfigurationOptions): Promise<ApiKeyResponse> {
        return this.api.createKey(param.createKeyRequest,  options).toPromise();
    }

    /**
     * Revoke an API key
     * @param param the request object
     */
    public deleteKeyWithHttpInfo(param: KeysApiDeleteKeyRequest, options?: ConfigurationOptions): Promise<HttpInfo<void>> {
        return this.api.deleteKeyWithHttpInfo(param.deleteKeyRequest,  options).toPromise();
    }

    /**
     * Revoke an API key
     * @param param the request object
     */
    public deleteKey(param: KeysApiDeleteKeyRequest, options?: ConfigurationOptions): Promise<void> {
        return this.api.deleteKey(param.deleteKeyRequest,  options).toPromise();
    }

    /**
     * List API keys for the authenticated user
     * @param param the request object
     */
    public getKeysWithHttpInfo(param: KeysApiGetKeysRequest = {}, options?: ConfigurationOptions): Promise<HttpInfo<Array<ListKeyResponse>>> {
        return this.api.getKeysWithHttpInfo( options).toPromise();
    }

    /**
     * List API keys for the authenticated user
     * @param param the request object
     */
    public getKeys(param: KeysApiGetKeysRequest = {}, options?: ConfigurationOptions): Promise<Array<ListKeyResponse>> {
        return this.api.getKeys( options).toPromise();
    }

}

import { ObservableObjectsApi } from "./ObservableAPI";
import { ObjectsApiRequestFactory, ObjectsApiResponseProcessor} from "../apis/ObjectsApi";

export interface ObjectsApiListObjectsRequest {
}

export class ObjectObjectsApi {
    private api: ObservableObjectsApi

    public constructor(configuration: Configuration, requestFactory?: ObjectsApiRequestFactory, responseProcessor?: ObjectsApiResponseProcessor) {
        this.api = new ObservableObjectsApi(configuration, requestFactory, responseProcessor);
    }

    /**
     * List all objects in the store
     * @param param the request object
     */
    public listObjectsWithHttpInfo(param: ObjectsApiListObjectsRequest = {}, options?: ConfigurationOptions): Promise<HttpInfo<Array<ObjectResponse>>> {
        return this.api.listObjectsWithHttpInfo( options).toPromise();
    }

    /**
     * List all objects in the store
     * @param param the request object
     */
    public listObjects(param: ObjectsApiListObjectsRequest = {}, options?: ConfigurationOptions): Promise<Array<ObjectResponse>> {
        return this.api.listObjects( options).toPromise();
    }

}
