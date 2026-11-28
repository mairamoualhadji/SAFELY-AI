
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using SafelyAI.Core.Interfaces;
using SafelyAI.Core.Models;

namespace SafelyAI.Response.IncidentManager
{
    public class IncidentManager : IIncidentManager
    {
        private readonly List<SecurityIncident> incidents = new();
        private readonly ReaderWriterLockSlim incidentsLock = new();

        public SecurityIncident CreateIncident(
            string title,
            string description,
            string type,
            string severity)
        {
            if (string.IsNullOrWhiteSpace(title) ||
                string.IsNullOrWhiteSpace(description) ||
                string.IsNullOrWhiteSpace(type))
            {
                throw new ArgumentException(
                    "Le titre, la description et le type sont obligatoires.");
            }

            string[] validSeverities =
                { "Faible", "Modéré", "Élevé", "Critique" };

            if (!validSeverities.Contains(severity))
            {
                throw new ArgumentException("Niveau de gravité invalide.");
            }

            var incident = new SecurityIncident
            {
                Id = Guid.NewGuid(),
                Title = title,
                Description = description,
                Type = type,
                Severity = severity,
                Status = "Ouvert",
                CreatedAt = DateTime.Now
            };

            incidentsLock.EnterWriteLock();
            try
            {
                incidents.Add(incident);
            }
            finally
            {
                incidentsLock.ExitWriteLock();
            }

            return incident;
        }

        public List<SecurityIncident> GetAllIncidents()
        {
            incidentsLock.EnterReadLock();
            try
            {
                return incidents.ToList();
            }
            finally
            {
                incidentsLock.ExitReadLock();
            }
        }

        public SecurityIncident? GetIncidentById(Guid id)
        {
            incidentsLock.EnterReadLock();
            try
            {
                return incidents.FirstOrDefault(i => i.Id == id);
            }
            finally
            {
                incidentsLock.ExitReadLock();
            }
        }

        public bool UpdateIncidentStatus(Guid id, string newStatus)
        {
            string[] validStatuses =
                { "Ouvert", "En cours", "Résolu" };

            if (string.IsNullOrWhiteSpace(newStatus) ||
                !validStatuses.Contains(newStatus))
            {
                return false;
            }

            incidentsLock.EnterWriteLock();
            try
            {
                var incident = incidents.FirstOrDefault(i => i.Id == id);

                if (incident == null)
                {
                    return false;
                }

                incident.Status = newStatus;
                incident.UpdatedAt = DateTime.Now;

                return true;
            }
            finally
            {
                incidentsLock.ExitWriteLock();
            }
        }
    }
}
