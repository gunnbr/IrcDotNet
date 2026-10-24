using System.Collections.Generic;

namespace IrcDotNet
{
    /// <summary>
    ///     Provides information used by an <see cref="IrcClient" /> for registering the connection as a service.
    /// </summary>
    /// <threadsafety static="true" instance="false" />
    public class IrcServiceRegistrationInfo : IrcRegistrationInfo
    {
        /// <summary>
        ///     Gets or sets the distribution of the service, which determines its visibility to users on specific servers.
        /// </summary>
        /// <value>
        ///     A wildcard expression for matching against the names of servers on which the service should be
        ///     visible.
        /// </value>
        public string Distribution { get; set; }

        /// <summary>
        ///     Gets or sets the description of the service to set upon registration.
        ///     The description cannot later be changed.
        /// </summary>
        /// <value>A description of the service.</value>
        public string Description { get; set; }
    }

    /// <summary>
    ///     Provides information used by an <see cref="IrcClient" /> for registering the connection as a user.
    /// </summary>
    /// <threadsafety static="true" instance="false" />
    public class IrcUserRegistrationInfo : IrcRegistrationInfo
    {
        /// <summary>
        ///     Gets or sets the user name of the local user to set upon registration.
        ///     The user name cannot later be changed.
        /// </summary>
        /// <value>The user name of the local user.</value>
        public string UserName { get; set; }

        /// <summary>
        ///     Gets or sets the real name of the local user to set upon registration.
        ///     The real name cannot later be changed.
        /// </summary>
        /// <value>The real name of the local user.</value>
        public string RealName { get; set; }

        /// <summary>
        ///     Gets or sets the modes of the local user to set initially.
        ///     The collection should not contain any characters except 'w' or 'i'.
        ///     The modes can be changed after registration.
        /// </summary>
        /// <value>A collection of modes to set on the local user.</value>
        public ICollection<char> UserModes { get; set; }

        /// <summary>
        ///     Gets or sets a value indicating whether to use SASL authentication during registration.
        ///     When set to <see langword="true"/>, the client will negotiate SASL capability and 
        ///     authenticate before completing registration.
        /// </summary>
        /// <value><see langword="true"/> to use SASL authentication; otherwise, <see langword="false"/>.</value>
        public bool UseSasl { get; set; }

        /// <summary>
        ///     Gets or sets the SASL authentication username.
        ///     If not specified, <see cref="IrcRegistrationInfo.NickName"/> will be used.
        ///     This property is only used when <see cref="UseSasl"/> is <see langword="true"/>.
        /// </summary>
        /// <value>The SASL authentication username.</value>
        public string SaslUsername { get; set; }

        /// <summary>
        ///     Gets or sets the SASL authentication password.
        ///     If not specified, <see cref="IrcRegistrationInfo.Password"/> will be used.
        ///     This property is only used when <see cref="UseSasl"/> is <see langword="true"/>.
        /// </summary>
        /// <value>The SASL authentication password.</value>
        public string SaslPassword { get; set; }
    }

    /// <summary>
    ///     Provides information used by an <see cref="IrcClient" /> for registering the connection with the server.
    /// </summary>
    /// <threadsafety static="true" instance="false" />
    public abstract class IrcRegistrationInfo
    {
        /// <summary>
        ///     Gets or sets the password for registering with the server.
        /// </summary>
        /// <value>The password for registering with the server.</value>
        public string Password { get; set; }

        /// <summary>
        ///     Gets or sets the nick name of the local user to set initially upon registration.
        ///     The nick name can be changed after registration.
        /// </summary>
        /// <value>The initial nick name of the local user.</value>
        public string NickName { get; set; }
    }
}
