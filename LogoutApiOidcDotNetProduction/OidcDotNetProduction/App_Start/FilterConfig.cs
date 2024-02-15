using System.Web;
using System.Web.Mvc;

namespace OIDC_DOT_NET_INTEGRATION_PRODUCTION
{
    public class FilterConfig
    {
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            filters.Add(new HandleErrorAttribute());
        }
    }
}
