import { ResponseContext, RequestContext, HttpFile, HttpInfo } from '../http/http';
import { Configuration, ConfigurationOptions, mergeConfiguration } from '../configuration'
import type { Middleware } from '../middleware';
import { Observable, of, from } from '../rxjsStub';
import {mergeMap, map} from  '../rxjsStub';
import { ApiKeyResponse } from '../models/ApiKeyResponse';
import { BackendConfigRequest } from '../models/BackendConfigRequest';
import { BackendConfigResponse } from '../models/BackendConfigResponse';
import { BackendType } from '../models/BackendType';
import { CreateKeyRequest } from '../models/CreateKeyRequest';
import { DeleteKeyRequest } from '../models/DeleteKeyRequest';
import { ListKeyResponse } from '../models/ListKeyResponse';
import { ObjectResponse } from '../models/ObjectResponse';

import { BackendApiRequestFactory, BackendApiResponseProcessor} from "../apis/BackendApi";
export class ObservableBackendApi {
    private requestFactory: BackendApiRequestFactory;
    private responseProcessor: BackendApiResponseProcessor;
    private configuration: Configuration;

    public constructor(
        configuration: Configuration,
        requestFactory?: BackendApiRequestFactory,
        responseProcessor?: BackendApiResponseProcessor
    ) {
        this.configuration = configuration;
        this.requestFactory = requestFactory || new BackendApiRequestFactory(configuration);
        this.responseProcessor = responseProcessor || new BackendApiResponseProcessor();
    }

    /**
     */
    public getBackendWithHttpInfo(_options?: ConfigurationOptions): Observable<HttpInfo<BackendConfigResponse>> {
        const _config = mergeConfiguration(this.configuration, _options);

        const requestContextPromise = this.requestFactory.getBackend(_config);
        // build promise chain
        let middlewarePreObservable = from<RequestContext>(requestContextPromise);
        for (const middleware of _config.middleware) {
            middlewarePreObservable = middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => middleware.pre(ctx)));
        }

        return middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => _config.httpApi.send(ctx))).
            pipe(mergeMap((response: ResponseContext) => {
                let middlewarePostObservable = of(response);
                for (const middleware of _config.middleware.reverse()) {
                    middlewarePostObservable = middlewarePostObservable.pipe(mergeMap((rsp: ResponseContext) => middleware.post(rsp)));
                }
                return middlewarePostObservable.pipe(map((rsp: ResponseContext) => this.responseProcessor.getBackendWithHttpInfo(rsp)));
            }));
    }

    /**
     */
    public getBackend(_options?: ConfigurationOptions): Observable<BackendConfigResponse> {
        return this.getBackendWithHttpInfo(_options).pipe(map((apiResponse: HttpInfo<BackendConfigResponse>) => apiResponse.data));
    }

    /**
     * @param backendConfigRequest
     */
    public putBackendWithHttpInfo(backendConfigRequest: BackendConfigRequest, _options?: ConfigurationOptions): Observable<HttpInfo<BackendConfigResponse>> {
        const _config = mergeConfiguration(this.configuration, _options);

        const requestContextPromise = this.requestFactory.putBackend(backendConfigRequest, _config);
        // build promise chain
        let middlewarePreObservable = from<RequestContext>(requestContextPromise);
        for (const middleware of _config.middleware) {
            middlewarePreObservable = middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => middleware.pre(ctx)));
        }

        return middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => _config.httpApi.send(ctx))).
            pipe(mergeMap((response: ResponseContext) => {
                let middlewarePostObservable = of(response);
                for (const middleware of _config.middleware.reverse()) {
                    middlewarePostObservable = middlewarePostObservable.pipe(mergeMap((rsp: ResponseContext) => middleware.post(rsp)));
                }
                return middlewarePostObservable.pipe(map((rsp: ResponseContext) => this.responseProcessor.putBackendWithHttpInfo(rsp)));
            }));
    }

    /**
     * @param backendConfigRequest
     */
    public putBackend(backendConfigRequest: BackendConfigRequest, _options?: ConfigurationOptions): Observable<BackendConfigResponse> {
        return this.putBackendWithHttpInfo(backendConfigRequest, _options).pipe(map((apiResponse: HttpInfo<BackendConfigResponse>) => apiResponse.data));
    }

}

import { KeysApiRequestFactory, KeysApiResponseProcessor} from "../apis/KeysApi";
export class ObservableKeysApi {
    private requestFactory: KeysApiRequestFactory;
    private responseProcessor: KeysApiResponseProcessor;
    private configuration: Configuration;

    public constructor(
        configuration: Configuration,
        requestFactory?: KeysApiRequestFactory,
        responseProcessor?: KeysApiResponseProcessor
    ) {
        this.configuration = configuration;
        this.requestFactory = requestFactory || new KeysApiRequestFactory(configuration);
        this.responseProcessor = responseProcessor || new KeysApiResponseProcessor();
    }

    /**
     * Create a new API key
     * @param createKeyRequest
     */
    public createKeyWithHttpInfo(createKeyRequest: CreateKeyRequest, _options?: ConfigurationOptions): Observable<HttpInfo<ApiKeyResponse>> {
        const _config = mergeConfiguration(this.configuration, _options);

        const requestContextPromise = this.requestFactory.createKey(createKeyRequest, _config);
        // build promise chain
        let middlewarePreObservable = from<RequestContext>(requestContextPromise);
        for (const middleware of _config.middleware) {
            middlewarePreObservable = middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => middleware.pre(ctx)));
        }

        return middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => _config.httpApi.send(ctx))).
            pipe(mergeMap((response: ResponseContext) => {
                let middlewarePostObservable = of(response);
                for (const middleware of _config.middleware.reverse()) {
                    middlewarePostObservable = middlewarePostObservable.pipe(mergeMap((rsp: ResponseContext) => middleware.post(rsp)));
                }
                return middlewarePostObservable.pipe(map((rsp: ResponseContext) => this.responseProcessor.createKeyWithHttpInfo(rsp)));
            }));
    }

    /**
     * Create a new API key
     * @param createKeyRequest
     */
    public createKey(createKeyRequest: CreateKeyRequest, _options?: ConfigurationOptions): Observable<ApiKeyResponse> {
        return this.createKeyWithHttpInfo(createKeyRequest, _options).pipe(map((apiResponse: HttpInfo<ApiKeyResponse>) => apiResponse.data));
    }

    /**
     * Revoke an API key
     * @param deleteKeyRequest
     */
    public deleteKeyWithHttpInfo(deleteKeyRequest: DeleteKeyRequest, _options?: ConfigurationOptions): Observable<HttpInfo<void>> {
        const _config = mergeConfiguration(this.configuration, _options);

        const requestContextPromise = this.requestFactory.deleteKey(deleteKeyRequest, _config);
        // build promise chain
        let middlewarePreObservable = from<RequestContext>(requestContextPromise);
        for (const middleware of _config.middleware) {
            middlewarePreObservable = middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => middleware.pre(ctx)));
        }

        return middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => _config.httpApi.send(ctx))).
            pipe(mergeMap((response: ResponseContext) => {
                let middlewarePostObservable = of(response);
                for (const middleware of _config.middleware.reverse()) {
                    middlewarePostObservable = middlewarePostObservable.pipe(mergeMap((rsp: ResponseContext) => middleware.post(rsp)));
                }
                return middlewarePostObservable.pipe(map((rsp: ResponseContext) => this.responseProcessor.deleteKeyWithHttpInfo(rsp)));
            }));
    }

    /**
     * Revoke an API key
     * @param deleteKeyRequest
     */
    public deleteKey(deleteKeyRequest: DeleteKeyRequest, _options?: ConfigurationOptions): Observable<void> {
        return this.deleteKeyWithHttpInfo(deleteKeyRequest, _options).pipe(map((apiResponse: HttpInfo<void>) => apiResponse.data));
    }

    /**
     * List API keys for the authenticated user
     */
    public getKeysWithHttpInfo(_options?: ConfigurationOptions): Observable<HttpInfo<Array<ListKeyResponse>>> {
        const _config = mergeConfiguration(this.configuration, _options);

        const requestContextPromise = this.requestFactory.getKeys(_config);
        // build promise chain
        let middlewarePreObservable = from<RequestContext>(requestContextPromise);
        for (const middleware of _config.middleware) {
            middlewarePreObservable = middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => middleware.pre(ctx)));
        }

        return middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => _config.httpApi.send(ctx))).
            pipe(mergeMap((response: ResponseContext) => {
                let middlewarePostObservable = of(response);
                for (const middleware of _config.middleware.reverse()) {
                    middlewarePostObservable = middlewarePostObservable.pipe(mergeMap((rsp: ResponseContext) => middleware.post(rsp)));
                }
                return middlewarePostObservable.pipe(map((rsp: ResponseContext) => this.responseProcessor.getKeysWithHttpInfo(rsp)));
            }));
    }

    /**
     * List API keys for the authenticated user
     */
    public getKeys(_options?: ConfigurationOptions): Observable<Array<ListKeyResponse>> {
        return this.getKeysWithHttpInfo(_options).pipe(map((apiResponse: HttpInfo<Array<ListKeyResponse>>) => apiResponse.data));
    }

}

import { ObjectsApiRequestFactory, ObjectsApiResponseProcessor} from "../apis/ObjectsApi";
export class ObservableObjectsApi {
    private requestFactory: ObjectsApiRequestFactory;
    private responseProcessor: ObjectsApiResponseProcessor;
    private configuration: Configuration;

    public constructor(
        configuration: Configuration,
        requestFactory?: ObjectsApiRequestFactory,
        responseProcessor?: ObjectsApiResponseProcessor
    ) {
        this.configuration = configuration;
        this.requestFactory = requestFactory || new ObjectsApiRequestFactory(configuration);
        this.responseProcessor = responseProcessor || new ObjectsApiResponseProcessor();
    }

    /**
     * List all objects in the store
     */
    public listObjectsWithHttpInfo(_options?: ConfigurationOptions): Observable<HttpInfo<Array<ObjectResponse>>> {
        const _config = mergeConfiguration(this.configuration, _options);

        const requestContextPromise = this.requestFactory.listObjects(_config);
        // build promise chain
        let middlewarePreObservable = from<RequestContext>(requestContextPromise);
        for (const middleware of _config.middleware) {
            middlewarePreObservable = middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => middleware.pre(ctx)));
        }

        return middlewarePreObservable.pipe(mergeMap((ctx: RequestContext) => _config.httpApi.send(ctx))).
            pipe(mergeMap((response: ResponseContext) => {
                let middlewarePostObservable = of(response);
                for (const middleware of _config.middleware.reverse()) {
                    middlewarePostObservable = middlewarePostObservable.pipe(mergeMap((rsp: ResponseContext) => middleware.post(rsp)));
                }
                return middlewarePostObservable.pipe(map((rsp: ResponseContext) => this.responseProcessor.listObjectsWithHttpInfo(rsp)));
            }));
    }

    /**
     * List all objects in the store
     */
    public listObjects(_options?: ConfigurationOptions): Observable<Array<ObjectResponse>> {
        return this.listObjectsWithHttpInfo(_options).pipe(map((apiResponse: HttpInfo<Array<ObjectResponse>>) => apiResponse.data));
    }

}
