
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
        private readonly IIncidentStore? store;
        private readonly ISecurityLogger? logger;

        public IncidentManager(IIncidentStore? store = null, ISecurityLogger? logger = null)
        {
            this.store = store;
            this.logger = logger;

            if (store == null)
                return;

            try
            {
                incidents.AddRange(store.Load());
            }
            catch (Exception ex)
            {
                logger?.LogError($"Impossible de charger les incidents persistés : {ex.Message}");
            }
        }

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
                TryPersist(() => store?.Save(incident));
            }
            finally
            {
                incidentsLock.ExitWriteLock();
            }

            TryLog(new SecurityEvent
            {
                EventType = "Incident créé",
                Description = incident.Title,
                Severity = incident.Severity,
                Source = "IncidentManager"
            });

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
                TryPersist(() => store?.Update(incident));
                TryLog(new SecurityEvent
                {
                    EventType = "Incident mis à jour",
                    Description = $"{incident.Title} -> {newStatus}",
                    Severity = incident.Severity,
                    Source = "IncidentManager"
                });

                return true;
            }
            finally
            {
                incidentsLock.ExitWriteLock();
            }
        }

        private void TryPersist(Action action)
        {
            try { action(); }
            catch (Exception ex) { logger?.LogError($"Persistance incident impossible : {ex.Message}"); }
        }

        private void TryLog(SecurityEvent securityEvent)
        {
            try { logger?.LogEvent(securityEvent); }
            catch { /* Une panne de journal ne doit pas annuler la réponse à l'incident. */ }
        }
    }
}
