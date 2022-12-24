using System.Collections;
using System.Collections.Generic;
using System;
namespace APLibrary.AirPlay.Utils
{
    public class EventEmitter<L, T>
    {
        private Dictionary<L, List<Action<T>>> handlers = new Dictionary<L, List<Action<T>>>();
        private Dictionary<L, List<Action<T>>> onceHandlers = new Dictionary<L, List<Action<T>>>();
        public EventEmitter()
        {
            handlers = new Dictionary<L, List<Action<T>>>();
        }
        public void on(L ev, Action<T> callback)
        {
            if (!handlers.ContainsKey(ev))
            {
                handlers[ev] = new List<Action<T>>();
            }
            handlers[ev].Add(callback);
        }
        public void once(L ev, Action<T> callback)
        {
            if (!onceHandlers.ContainsKey(ev))
            {
                onceHandlers[ev] = new List<Action<T>>();
            }
            onceHandlers[ev].Add(callback);
        }
        public void off(L ev, Action<T> callback)
        {
            if (!handlers.ContainsKey(ev))
            {
                return;
            }

            List<Action<T>> l = handlers[ev];
            if (!l.Contains(callback))
            {
                return;
            }

            l.Remove(callback);
            if (l.Count == 0)
            {
                handlers.Remove(ev);
            }
        }
        public void emit(L name, T data)
        {
            if (!handlers.ContainsKey(name))
            {
                if (name.GetType() == typeof(Exception))
                {
                    throw name as Exception;
                }
                return;
            }
            foreach (Action<T> handler in this.handlers[name])
            {
                try
                {
                    handler(data);
                }
                catch (Exception ex)
                {
                    throw ex;
                }
            }
            if (!onceHandlers.ContainsKey(name))
            {
                if (name.GetType() == typeof(Exception))
                {
                    throw name as Exception;
                }
                return;
            }
            foreach (Action<T> onceHandler in this.onceHandlers[name])
            {
                try
                {
                    onceHandler(data);
                    this.onceHandlers.Remove(name);
                }
                catch (Exception ex)
                {
                    throw ex;
                }
            }
        }
        public void removeAllListeners()
        {
            handlers = new Dictionary<L, List<Action<T>>>();
            onceHandlers = new Dictionary<L, List<Action<T>>>();
        }
    }
}    