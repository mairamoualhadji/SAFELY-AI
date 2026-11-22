
using System;
using System.Collections.Generic;
using System.Linq;
using SafelyAI.Core.Interfaces;
using SafelyAI.Core.Models;

namespace SafelyAI.Response.IncidentManager
{
    public class IncidentManager : IIncidentManager
    {
        private readonly List<SecurityIncident> incidents = new();

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

            incidents.Add(incident);

            return incident;
        }

        public List<SecurityIncident> GetAllIncidents()
        {
            return incidents.ToList();
        }

        public SecurityIncident? GetIncidentById(Guid id)
        {
            return incidents.FirstOrDefault(i => i.Id == id);
        }

        public bool UpdateIncidentStatus(Guid id, string newStatus)
        {
            string[] validStatuses =
                { "Ouvert", "En cours", "Résolu" };

            if (!validStatuses.Contains(newStatus))
            {
                return false;
            }

            var incident = GetIncidentById(id);

            if (incident == null)
            {
                return false;
            }

            incident.Status = newStatus;
            incident.UpdatedAt = DateTime.Now;

            return true;
        }
    }
}
