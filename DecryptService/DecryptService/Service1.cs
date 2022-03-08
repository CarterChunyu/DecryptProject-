using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;

namespace DecryptService
{
    public partial class Service1 : ServiceBase
    {
        private static HttpListener _httpListener;
        public Service1()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            if (_httpListener == null)
                _httpListener = new HttpListener();
            if (!_httpListener.Prefixes.Contains(@"http://*:3333/"))
                _httpListener.Prefixes.Add(@"http://*:3333/");
            _httpListener.Start();
            ListnerHelper helper =new ListnerHelper();
            helper.InitializeHttplistener(ref _httpListener);
        }
        protected override void OnStop()
        {
            _httpListener.Stop();
        }
    }
}
