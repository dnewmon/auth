import { AxiosError } from 'axios';
import { PropsWithChildren, SyntheticEvent, ReactNode, startTransition, useEffect, useRef, useState } from 'react';

export type BootstrapResponsiveSize = 'sm' | 'md' | 'lg' | 'xl' | 'xxl';

export function useBootstrapBreakpoints(): [(size: BootstrapResponsiveSize) => number, () => number] {
    const get_breakpoint = (size: BootstrapResponsiveSize) => {
        switch (size) {
            case 'sm':
                return 576;
            case 'md':
                return 768;
            case 'lg':
                return 992;
            case 'xl':
                return 1200;
            case 'xxl':
                return 1400;
        }
    };

    const get_client_width = () => window.innerWidth;
    return [get_breakpoint, get_client_width];
}

export type ReactArrayResponse<T> = [T[], (value: T[]) => void, (value: T) => T[], (index: number, value: T) => T[], (index: number) => T[]];

export function useArray<T>(init_state?: T[]): ReactArrayResponse<T> {
    const start_state = init_state === undefined ? [] : init_state;
    const [state, set_state] = useState<T[]>(start_state);

    const add_item = (value: T) => {
        let new_state = [...state];
        new_state.push(value);
        set_state(new_state);
        return new_state;
    };

    const update_item = (index: number, value: T) => {
        const new_state = [...state];
        new_state[index] = value;
        set_state(new_state);
        return new_state;
    };

    const delete_item = (index: number) => {
        let new_state: T[] = [];
        new_state = new_state.concat(state.slice(0, index)).concat(state.slice(index + 1));

        set_state(new_state);
        return new_state;
    };

    return [state, set_state, add_item, update_item, delete_item];
}

export function useVolatileState<T>(init_value: T): [T, () => T, (value: T) => void] {
    const [state, set_state] = useState<T>(init_value);
    const ref_state = useRef<T>();
    ref_state.current = undefined;

    const get_value_fn = () => (ref_state.current !== undefined ? ref_state.current : state);
    const set_value_fn = (value: T) => {
        ref_state.current = value;
        set_state(value);
    };

    return [state, get_value_fn, set_value_fn];
}

export function useMutatedRef<T>(init_value: T) {
    const ref = useRef<T>(init_value);
    return ref.current;
}

export function useImmutableRef<T>(init_value: T): [() => T, (value: T) => void] {
    const ref = useRef<T>(init_value);

    const update_ref = (value: T) => {
        ref.current = value;
    };

    const read_ref = () => {
        return ref.current;
    };

    return [read_ref, update_ref];
}

export function useCommitState<T>(init_value: T, update: (value: T) => void): [T, (value: T) => void, () => void] {
    const [scratch_value, set_scratch_value] = useState<T>(init_value);
    const commit_fn = () => update(scratch_value);
    return [scratch_value, set_scratch_value, commit_fn];
}

export function useTransactionState<T>(init_value: T) {
    const [real_value, set_real_value] = useState<T>(init_value);
    const [scratch_value, set_scratch_value] = useState<T>(init_value);

    const commit_fn = () => set_real_value(scratch_value);
    const revert_fn = () => set_scratch_value(real_value);

    return [real_value, set_real_value, scratch_value, set_scratch_value, commit_fn, revert_fn];
}

export function usePreventDefault<T extends Function, U extends SyntheticEvent>(fn: T): (event: U) => void {
    return (event: U) => {
        event.preventDefault();
        return fn(event);
    };
}

export function useRefElement<T>(): [Nullable<T>, React.MutableRefObject<Nullable<T>>] {
    const ref = useRef<T>(null);
    return [ref.current, ref];
}

export function useImmutableRefElement<T>(): [() => Nullable<T>, React.MutableRefObject<Nullable<T>>] {
    const ref = useRef<T>(null);
    const read_ref = () => {
        return ref.current;
    };

    return [read_ref, ref];
}

function _readStorage<T>(storage_api: Storage, name: string, initial_value: T): T {
    let ret_value = initial_value;
    let json_str = storage_api.getItem(name);

    if (json_str !== null) {
        ret_value = JSON.parse(json_str) as T;
    }

    return ret_value;
}

function _writeStorage<T>(storage_api: Storage, name: string, value?: T): void {
    if (value !== undefined) {
        storage_api.setItem(name, JSON.stringify(value));
    } else {
        storage_api.removeItem(name);
    }
}

function _useStorage<T = any>(storage_api: Storage, name: string, initial_value: T): [T, (value: T) => void] {
    const setStorageValue = function (value?: T): void {
        _writeStorage(storage_api, name, value);
    };

    const ret_value = _readStorage(storage_api, name, initial_value);
    return [ret_value, setStorageValue];
}

export function useSessionStorage<T>(name: string, initial_value: T): [T, (value: T) => void] {
    return _useStorage<T>(sessionStorage, name, initial_value);
}

export function useLocalStorage<T>(name: string, initial_value: T): [T, (value: T) => void] {
    return _useStorage<T>(localStorage, name, initial_value);
}

export function readLocalStorage<T>(name: string, initial_value: T): T {
    return _readStorage<T>(localStorage, name, initial_value);
}

export function readSessionStorage<T>(name: string, initial_value: T): T {
    return _readStorage<T>(sessionStorage, name, initial_value);
}

export function writeLocalStorage<T>(name: string, initial_value: T): void {
    _writeStorage<T>(localStorage, name, initial_value);
}

export function writeSessionStorage<T>(name: string, initial_value: T): void {
    _writeStorage<T>(sessionStorage, name, initial_value);
}

export class CookieSpec {
    value?: Nullable<string>;
    expires?: Date;
    max_age?: number;
    path?: string;
    samesite?: 'lax' | 'strict' | 'none';
    secure?: boolean;
}

export type UpdateCookieType = Nullable<string> | CookieSpec;

export function useCookie(name: string, include_state: boolean): [Nullable<string>, (value: UpdateCookieType) => void] {
    const react_state = include_state ? useState<Nullable<string>>(null) : null;

    const start_idx = document.cookie.indexOf(name);
    let cookie_value = null;
    if (start_idx !== -1) {
        const end_idx1 = document.cookie.length;
        const end_idx2 = document.cookie.indexOf(';', start_idx);
        const end_idx = end_idx2 !== -1 ? Math.min(end_idx1, end_idx2) : end_idx1;

        const offset_length = name.length + 1;
        cookie_value = document.cookie.substring(start_idx + offset_length, end_idx);
    }

    const _set_cookie_internal = (spec: CookieSpec) => {
        const value_exp = spec.value !== undefined && spec.value !== null ? spec.value : ``;
        const expires_exp = spec.expires !== undefined ? `;expires=${spec.expires.toUTCString()}` : ``;
        const max_age_exp = spec.max_age !== undefined ? `;max-age=${spec.max_age}` : ``;
        const path_exp = spec.path !== undefined ? `;path=${encodeURIComponent(spec.path)}` : ``;
        const samesite_exp = spec.samesite !== undefined ? `;samesite=${spec.samesite}` : ``;
        const secure_exp = spec.secure !== undefined ? `;secure=${spec.secure}` : ``;

        const cookie_spec = `${name}=${value_exp}${expires_exp}${max_age_exp}${path_exp}${samesite_exp}${secure_exp}`;
        console.log(cookie_spec);
        document.cookie = cookie_spec;

        if (react_state !== null) {
            react_state[1](value_exp);
        }
    };

    const set_cookie = (value: UpdateCookieType) => {
        if (!(value instanceof CookieSpec)) {
            const new_spec = new CookieSpec();
            new_spec.value = value;

            if (value === null) {
                new_spec.expires = new Date(new Date().getTime() - 2000);
            }

            _set_cookie_internal(new_spec);
            return;
        }

        _set_cookie_internal(value);
    };

    return [cookie_value, set_cookie];
}

export function useTimer(): [(handler: TimerHandler, timeout: number) => void, () => void] {
    const timer_ref = useRef<number>(-1);

    const trigger = (handler: TimerHandler, timeout: number) => {
        clearTimeout(timer_ref.current);
        timer_ref.current = setTimeout(handler, timeout);
    };

    const cancel = () => {
        clearTimeout(timer_ref.current);
    };

    return [trigger, cancel];
}

export function useInterval(callback: TimerHandler, delay: number) {
    useEffect(() => {
        const id = setInterval(callback, delay);

        return () => {
            clearInterval(id);
        };
    }, [delay, callback]);
}

export type Nullable<T> = T | null;

export enum ApiState {
    NotLoaded,
    Loading,
    Loaded,
    Error,
}

export type UseApiResponse<T, U extends any[]> = [
    (...args: U) => Promise<T>, // invalidate method
    Nullable<T>, // current value
    ApiState, // api state
    any // error
];

export function useApi<T, U extends any[]>(fetcher: (...args: U) => Promise<T>, update_state?: (value: Nullable<T>) => void): UseApiResponse<T, U> {
    const [api_state, set_api_state] = useState<ApiState>(ApiState.NotLoaded);
    const [api_data, set_api_data] = useState<Nullable<T>>(null);
    const [api_error, set_api_error] = useState<any>(null);

    const execute_fetch = (...args: U): Promise<T> => {
        set_api_state(ApiState.Loading);

        return fetcher(...args)
            .then((data) => {
                startTransition(() => {
                    set_api_state(ApiState.Loaded);
                    set_api_error(null);
                    set_api_data(data);

                    if (update_state) {
                        update_state(data);
                    }
                });

                return data;
            })
            .catch((error) => {
                startTransition(() => {
                    set_api_state(ApiState.Error);
                    set_api_data(null);
                    set_api_error(error);

                    if (update_state) {
                        update_state(null);
                    }
                });

                return error;
            });
    };

    return [execute_fetch, api_data, api_state, api_error];
}

export function usePreloadedApi<T, U extends any[]>(data: T, fetcher: (...args: U) => Promise<T>, update_state?: (value: Nullable<T>) => void): UseApiResponse<T, U> {
    const [initial_load, set_initial_load] = useState<boolean>(true);

    return useApi(
        async (...args: U) => {
            if (initial_load) {
                return data;
            }

            return await fetcher(...args);
        },
        (data) => {
            set_initial_load(false);
            if (update_state) {
                return update_state(data);
            }
        }
    );
}

export function useDebouncedEffect(callback_fn: () => void, deps?: any[], timeout?: number) {
    useEffect(() => {
        if (timeout === undefined) {
            timeout = 250;
        }

        let timer_id = setTimeout(() => {
            callback_fn();
        }, timeout);

        return () => {
            clearTimeout(timer_id);
        };
    }, deps);
}

export interface ConditionalProps extends PropsWithChildren {
    display: boolean;
}

export function Conditional({ display, children }: ConditionalProps) {
    return display ? children : <></>;
}

export interface RenderConditionalProps {
    display: boolean;
    render: () => ReactNode;
}

export function RenderConditional({ display, render }: RenderConditionalProps) {
    return display ? render() : <></>;
}

export interface RenderNotNullProps<T> {
    state: Nullable<T>;
    render: (value: T) => ReactNode;
}

export function RenderNotNull<T>({ state, render }: RenderNotNullProps<T>) {
    return state !== null ? render(state) : <></>;
}

export interface ApiSuspenseProps extends PropsWithChildren {
    api_state?: ApiState;
    api_states?: ApiState[];
    suspense: ReactNode;
    delay?: number;
}

export function ApiSuspense({ api_state, api_states, suspense, delay, children }: ApiSuspenseProps) {
    const [show_suspense, set_show_suspense] = useState<boolean>(false);
    const [trigger, cancel] = useTimer();

    const timeout = delay !== undefined ? delay : 500;

    const is_api_loading = () => {
        if (api_state === ApiState.Loading) {
            return true;
        } else if (api_states !== undefined) {
            return api_states.find((state) => state === ApiState.Loading) !== undefined;
        }

        return false;
    };

    useEffect(() => {
        if (is_api_loading()) {
            trigger(() => {
                set_show_suspense(is_api_loading());
            }, timeout);
        } else if (show_suspense) {
            set_show_suspense(false);
        }

        return cancel;
    }, [api_state]);

    return show_suspense ? suspense : children;
}

export interface ApiErrorProps extends PropsWithChildren {
    api_error: AxiosError;
    render_error?: (message: string) => ReactNode;
}

export function ApiErrorFallback({ api_error, children, render_error }: ApiErrorProps) {
    if (api_error !== undefined && api_error !== null) {
        let error_prefix = `${api_error.code}: `;
        let error_message = api_error.message;
        let styles = 'p-2 text-bg-danger rounded-2';

        if (api_error.response) {
            const response_data: any = api_error.response.data as any;
            error_message = response_data;

            if (response_data.error) {
                error_message = response_data.error;
                error_prefix = '';
            } else if (response_data.message) {
                error_message = response_data.message;
                error_prefix = '';
            } else {
                error_message = `${error_message}`;

                if (api_error.response !== null && api_error.response !== undefined) {
                    const error_response = api_error.response;

                    if (error_response.headers !== null && error_response.headers !== undefined) {
                        const response_headers = error_response.headers;

                        // @ts-ignore
                        const content_type = response_headers.getContentType();

                        if (content_type !== null && content_type !== undefined && typeof content_type === 'string' && content_type.indexOf('text/html') === 0) {
                            let elm = document.createElement('div');
                            elm.innerHTML = error_message;
                            error_message = elm.innerText;
                            styles += 'font-monospace white-space-pre';
                        }
                    }
                }
            }
        }

        const full_error_message = `${error_prefix}${error_message}`;

        if (render_error === undefined) {
            return <div className={styles}>{full_error_message}</div>;
        } else {
            return render_error(full_error_message);
        }
    }

    return children;
}
